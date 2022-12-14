/*-
 * Copyright (c) 2017
 * Federal Office for Information Security (BSI),
 * Godesberger Allee 185-189,
 * 53175 Bonn, Germany,
 * phone: +49 228 99 9582-0,
 * fax: +49 228 99 9582-5400,
 * e-mail: bsi@bsi.bund.de
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.bund.bsi.tr_esor.checktool.validation.default_impl;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;

import de.bund.bsi.tr_esor.checktool.validation.NoValidatorException;
import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.Validator;
import de.bund.bsi.tr_esor.checktool.validation.ValidatorFactory;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;


/**
 * Base class with common methods for validation.
 *
 * @author MO
 * @param <T> class to be validated
 * @param <C> context to be used by this validator
 * @param <R> report part to be generated
 */
public abstract class BaseValidator<T, C extends ValidationContext<?>, R extends ReportPart>
  implements Validator<T, C, R>
{

  /**
   * Validation context, set by the ValidatorFactory.
   */
  protected C ctx;

  @Override
  public void setContext(C context)
  {
    Objects.requireNonNull(context, "The context may not be null");
    var clazz = getRequiredContextClass();
    if (!clazz.isInstance(context))
    {
      throw new IllegalArgumentException("Context is not a " + clazz.getName());
    }
    ctx = clazz.cast(context);
  }

  /**
   * Returns the type of context needed by this class.
   */
  protected abstract Class<C> getRequiredContextClass();

  /**
   * Performs the actual validation after generic check(s) has been done.
   *
   * @param ref
   * @param toCheck
   */
  protected abstract R validateInternal(Reference ref, T toCheck);

  @Override
  public final R validate(Reference ref, T toCheck)
  {
    if (!ctx.getReference().isAncestorOf(ref))
    {
      throw new IllegalArgumentException("Checked reference does not belong to context");
    }
    return validateInternal(ref, toCheck);
  }

  /**
   * Calls an other validator for some child element and returns the respective report part.
   *
   * @param toValidate child element to validate
   * @param ref human-readable description where that object came from
   * @param prepareValidator optional, do some setup with the validator. The respective type cannot be bound
   *          properly, any setup will require so cast.
   * @param emptyReport creates a report of wanted type (must be exactly the type required as method return
   *          value)
   */
  @SuppressWarnings("unchecked")
  protected <RP extends ReportPart, TP> RP callValidator(TP toValidate,
                                                         Reference ref,
                                                         Consumer<Validator<?, ?, ?>> prepareValidator,
                                                         Supplier<RP> emptyReport,
                                                         Class<RP> reportType)
  {
    try
    {
      var val = (Validator<TP, ?, RP>)ValidatorFactory.getInstance()
                                                      .getValidator(toValidate.getClass(), reportType, ctx);
      if (prepareValidator != null)
      {
        prepareValidator.accept(val);
      }
      return val.validate(ref, toValidate);
    }
    catch (NoValidatorException e)
    {
      var er = emptyReport.get();
      if (er != null)
      {
        er.setNoValidator(e);
      }
      return er;
    }
  }

  /**
   * Convenience for {@link #callValidator(Object, Reference, Consumer, Supplier, Class)} in case of report
   * part has constructor using only {@link Reference} parameter.
   *
   * @param toValidate
   * @param ref
   * @param prepareValidator
   * @param reportType
   */
  protected <RP extends ReportPart, TP> RP callValidator(TP toValidate,
                                                         Reference ref,
                                                         Consumer<Validator<?, ?, ?>> prepareValidator,
                                                         Class<RP> reportType)
  {
    return callValidator(toValidate, ref, prepareValidator, () -> supplyReport(reportType, ref), reportType);
  }

  /**
   * Convenience for {@link #callValidator(Object, Reference, Consumer, Class)} in case no preparation of the
   * validator is necessary.
   *
   * @param toValidate
   * @param ref
   * @param reportType
   */
  protected <RP extends ReportPart, TP> RP callValidator(TP toValidate, Reference ref, Class<RP> reportType)
  {
    return callValidator(toValidate, ref, null, () -> supplyReport(reportType, ref), reportType);
  }

  private <RP extends ReportPart> RP supplyReport(Class<RP> type, Reference ref)
  {
    RP r = null;
    try
    {
      r = type.getConstructor(Reference.class).newInstance(ref);
    }
    catch (ReflectiveOperationException e)
    {
      throw new IllegalArgumentException("no constructor with parameter Reference in type " + type.getName(),
                                         e);
    }
    return r;
  }

  /**
   * Supplier for byte arrays which may throw an {@link IOException}.
   */
  @FunctionalInterface
  interface ByteArraySupplier
  {

    byte[] get() throws IOException;
  }

  /**
   * Returns calculated hash provided by supplier with the given hashOID. If computation fails the result of
   * report is updated according to the occurred exception.
   *
   * @param supplier
   * @param hashOID
   * @param ref
   * @param report
   * @return <code>null</code> if computation failed
   */
  @SuppressWarnings("PMD.ReturnEmptyArrayRatherThanNull")
  protected byte[] computeHash(ByteArraySupplier supplier, String hashOID, Reference ref, ReportPart report)
  {
    try
    {
      return ValidatorFactory.getInstance().getHashCreator().calculateHash(supplier.get(), hashOID);
    }
    catch (IOException e)
    {
      report.updateCodes(ValidationResultMajor.INVALID,
                         "FormatError",
                         MinorPriority.IMPORTANT,
                         "cannot get content to hash " + e.getMessage(),
                         ref);
    }
    catch (NoSuchAlgorithmException e)
    {
      report.updateCodes(ValidationResultMajor.INDETERMINED,
                         "InternalError",
                         MinorPriority.IMPORTANT,
                         e.getMessage(),
                         ref);
    }
    catch (ReflectiveOperationException e)
    {
      report.updateCodes(ValidationResultMajor.INDETERMINED,
                         "InternalError",
                         MinorPriority.IMPORTANT,
                         "cannot get hash calculator " + e.getMessage(),
                         new Reference("configuration"));
    }
    return null;
  }
}
