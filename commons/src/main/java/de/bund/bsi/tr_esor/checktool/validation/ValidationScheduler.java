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
package de.bund.bsi.tr_esor.checktool.validation;

import java.util.List;
import java.util.stream.Collectors;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.xml.VRCreator;


/**
 * Eventually triggers the validation of elements.
 *
 * @author TT
 */
public final class ValidationScheduler
{

  private static ValidatorFactory factory = ValidatorFactory.getInstance();

  private ValidationScheduler()
  {
    // static only
  }

  /**
   * Validates all the given objects and their children and returns a verification report.
   *
   * @param contexts sorted out elements and required data to validate each one
   */
  @SuppressWarnings("PMD.NullAssignment")
  public static VerificationReportType validate(List<ValidationContext<?>> contexts)
  {
    var reports = contexts.stream().map(ValidationScheduler::doValidation).collect(Collectors.toList());
    return VRCreator.createReport(reports,
                                  contexts.isEmpty() ? null : contexts.get(0).getReturnVerificationReport());
  }

  private static <T> ReportPart doValidation(ValidationContext<T> context)
  {
    try
    {
      if (!factory.isProfileSupported(context.getProfileName()))
      {
        return ReportPart.forNoProfile(context.getReference(), context.getProfileName());
      }
      Validator<T, ?, ReportPart> val = factory.getValidator(context.getTargetClass(),
                                                             ReportPart.class,
                                                             context);
      return val.validate(context.getReference(), context.getObjectToValidate());
    }
    catch (NoValidatorException e)
    {
      // may happen after inconsistent extension of the application
      return ReportPart.forNoValidator(context.getReference(), e);
    }
  }
}
