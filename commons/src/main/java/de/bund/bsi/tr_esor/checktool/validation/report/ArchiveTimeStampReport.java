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

import java.util.ArrayList;
import java.util.List;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ArchiveTimeStampValidityType;

import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;


/**
 * Report class for archive time stamps.
 *
 * @author HMA, TT
 */
public class ArchiveTimeStampReport extends ReportPart implements OutputCreator<ArchiveTimeStampValidityType>
{

  private final ArchiveTimeStampValidityType xmlReport;

  private final List<Reference> idsOfMissingHashValues = new ArrayList<>();

  /**
   * Creates new instance.
   *
   * @param ref
   */
  public ArchiveTimeStampReport(Reference ref)
  {
    super(ref);
    xmlReport = XmlHelper.FACTORY_OASIS_VR.createArchiveTimeStampValidityType();
  }

  @Override
  public ArchiveTimeStampValidityType getFormatted()
  {
    return xmlReport;
  }

  @Override
  public Class<ArchiveTimeStampValidityType> getTargetClass()
  {
    return ArchiveTimeStampValidityType.class;
  }

  /**
   * Sets the algorithm validity report.
   *
   * @param reportPart
   */
  public void addChild(AlgorithmValidityReport reportPart)
  {
    updateCodes(reportPart);
    xmlReport.setDigestAlgorithm(reportPart.getFormatted());
  }

  /**
   * Sets the time stamp report.
   *
   * @param reportPart
   */
  public void addChild(TimeStampReport reportPart)
  {
    updateCodes(reportPart);
    xmlReport.setTimeStamp(reportPart.getFormatted());
  }

  /**
   * For debugging purposes: Records the identifier of an object whose hash was missing.
   *
   * @param ref
   */
  public void addIdOfMissingHash(Reference ref)
  {
    idsOfMissingHashValues.add(ref);
  }

  /**
   * Sets the value of the formatOk report part.
   *
   * @param formatOk
   */
  public void setFormatOk(FormatOkReport formatOk)
  {
    updateCodes(formatOk);
    xmlReport.setFormatOK(formatOk.getOverallResultVerbose());
  }
}
