/*-
 * Copyright (c) 2019
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
package de.bund.bsi.tr_esor.checktool.validation.signatures;

import oasis.names.tc.dss._1_0.core.schema.InternationalStringType;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Enricher for additional nodes in the VerificationReport.
 *
 * @author intemann
 */

public class VerificationReportEnricher
{

  private static final Logger LOG = LoggerFactory.getLogger(VerificationReportEnricher.class);

  /**
   * This method enriches a given <code>VerificationReportType</code> with additional nodes as specified.
   *
   * @param vr
   */
  public void enrich(VerificationReportType vr)
  {
    // if no verification report exist - may be eCard Service not avail.- nothing to do here
    if (vr == null)
    {
      LOG.debug("Verification Report is NULL!");
      return;
    }

    if (vr.getIndividualReport() == null)
    {
      LOG.debug("List of Individual Reports ist NULL!");
      return;
    }

    // If vr has no individual reports and thus no signed data as input for verification
    if (vr.getIndividualReport().isEmpty())
    {
      IndividualReportType indivReport = new IndividualReportType();
      Result result = new Result();
      indivReport.setResult(result);
      result.setResultMajor(ECardResultMajor.OK);
      InternationalStringType resultMessage = new InternationalStringType();
      resultMessage.setLang("en");
      resultMessage.setValue("No signature found in data object.");
      result.setResultMessage(resultMessage);
      vr.getIndividualReport().add(indivReport);
    }
  }
}
