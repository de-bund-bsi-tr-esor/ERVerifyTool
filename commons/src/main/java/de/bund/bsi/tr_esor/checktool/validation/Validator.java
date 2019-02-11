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

import de.bund.bsi.tr_esor.checktool.validation.report.OutputCreator;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;


/**
 * Validates objects and returns some report. Implementing classes must have a constructor without parameters
 * or a constructor taking a parameter of type Map&lt;String, String&gt;.
 *
 * @author TT
 * @param <T> type of object to be checked
 * @param <C> type of required context
 * @param <R> type of created report
 */
@SuppressWarnings("rawtypes") // C extends ValidationContext<?> cannot be resolved for implementing classes
public interface Validator<T, C extends ValidationContext, R extends ReportPart>
{

  /**
   * Validates a given object.
   *
   * @param ref unique identifier of the validated object within the validation request
   * @param toCheck object to validate
   * @return Validation result which contains some overall verdict and some specific details. Result type must
   *         be supported by the used ReportGenerator class(es). If in doubt, let it implement
   *         {@link OutputCreator}&lt; {@link IndividualReportType} &gt;.
   */
  R validate(Reference ref, T toCheck);

  /**
   * Sets the context object for validating the root element.
   *
   * @param context may contain information collected in one part of the object tree and needed while
   *          validating some other part
   * @throws IllegalArgumentException if this validator requires another type of context
   */
  void setContext(C context);

}
