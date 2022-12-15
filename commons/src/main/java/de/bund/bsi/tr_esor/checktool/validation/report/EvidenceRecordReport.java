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
package de.bund.bsi.tr_esor.checktool.validation.report;

import de.bund.bsi.tr_esor.checktool.xml.VRCreator;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.vr.EvidenceRecordValidityType;
import de.bund.bsi.tr_esor.vr.EvidenceRecordValidityType.ArchiveTimeStampSequence;


/**
 * Wraps the validation results of an evidence record.
 *
 * @author HMA, TT
 */
public class EvidenceRecordReport extends ReportPart implements OutputCreator<EvidenceRecordValidityType>
{

  private final EvidenceRecordValidityType xmlReport;

  /**
   * Creates new instance.
   *
   * @param ref
   */
  public EvidenceRecordReport(Reference ref)
  {
    super(ref);
    xmlReport = XmlHelper.FACTORY_ESOR_VR.createEvidenceRecordValidityType();
    xmlReport.setVersion("urn:ietf:rfc:4998");
    xmlReport.setReportVersion("1.3.0");
  }

  @Override
  public EvidenceRecordValidityType getFormatted()
  {
    return xmlReport;
  }

  @Override
  public Class<EvidenceRecordValidityType> getTargetClass()
  {
    return EvidenceRecordValidityType.class;
  }

  /**
   * Sets the report for the archive time stamp sequence.
   *
   * @param validate
   */
  public void addChild(ATSSequenceReport validate)
  {
    updateCodes(validate);
    xmlReport.setArchiveTimeStampSequence(VRCreator.translate(validate, ArchiveTimeStampSequence.class));
  }

  /**
   * Sets the report for the algorithm validity.
   *
   * @param validate
   */
  public void addChild(AlgorithmValidityReport validate)
  {
    updateCodes(validate);
    xmlReport.getDigestAlgorithm().add(validate.getFormatted());
  }

  /**
   * Sets the value of the formatOk report part.
   *
   * @param formatOk
   */
  public void setFormatOk(ReportPart formatOk)
  {
    updateCodes(formatOk);
    xmlReport.setFormatOK(formatOk.getOverallResultVerbose());
  }

}
