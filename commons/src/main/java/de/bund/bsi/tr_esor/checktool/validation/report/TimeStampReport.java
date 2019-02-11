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

import java.util.List;

import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificatePathValidityVerificationDetailType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificateValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.SignatureValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.TimeStampValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationResultType;


/**
 * Wraps the findings of a time stamp validation.
 *
 * @author MO
 */
public class TimeStampReport extends ReportPart implements OutputCreator<TimeStampValidityType>
{

  private final TimeStampValidityType xmlReport;

  private FormatOkReport parsedFormatOk;

  /**
   * Constructs a new report for given timestamp reference.
   *
   * @param reference
   */
  public TimeStampReport(Reference reference)
  {
    super(reference);
    xmlReport = XmlHelper.FACTORY_OASIS_VR.createTimeStampValidityType();
  }

  /**
   * Constructs a new report from an existing time stamp verification result.
   *
   * @param reference
   * @param tsvt TimeStampValidityType from an existing VerificationReport
   */
  public TimeStampReport(Reference reference, TimeStampValidityType tsvt, Result result)
  {
    super(reference);
    parsedFormatOk = parseFormatOkFromReport(tsvt);
    xmlReport = tsvt;
    updateCodesFromXmlReport();
    updateCodesFromVR(reference, result);
  }

  /**
   * Parses the found formatOk information, making sure no information will be lost in case some additional
   * checks are added to this class. Furthermore, this is necessary for getting the message propagation
   * correct.
   *
   * @param tsvt
   */
  private FormatOkReport parseFormatOkFromReport(TimeStampValidityType tsvt)
  {
    FormatOkReport result = new FormatOkReport(getReference());
    updateCodesFromVR(getReference(), tsvt.getFormatOK(), result);
    return result;
  }

  /**
   * Adds the format check result to the overall result.
   */
  public void setFormatOk(FormatOkReport formatOk)
  {
    xmlReport.setFormatOK(formatOk.getOverallResultVerbose());
    updateCodes(formatOk);
  }

  /**
   * Updates codes from present XML time stamp verification report. Importance of minor codes is determined by
   * the order of checking in this method, i.e. formatOK is more important than certificatePathValidity.
   */
  private void updateCodesFromXmlReport()
  {
    updateCodesFromCertPath();
    if (xmlReport.getMessageHashAlgorithm() != null
        && xmlReport.getMessageHashAlgorithm().getSuitability() != null)
    {
      updateCodesFromVR(getReference().newChild("messageHash"),
                        xmlReport.getMessageHashAlgorithm().getSuitability(),
                        this);
    }
    updateCodesFromSig(getReference(), xmlReport.getSignatureOK());
  }

  private void updateCodesFromCertPath()
  {
    Reference certPathRef = getReference().newChild("CertPath");
    if (xmlReport.getCertificatePathValidity().getPathValidityDetail() != null)
    {
      CertificatePathValidityVerificationDetailType detail = xmlReport.getCertificatePathValidity()
                                                                      .getPathValidityDetail();
      List<CertificateValidityType> certValidity = detail.getCertificateValidity();
      for ( int i = certValidity.size() - 1 ; i >= 0 ; i-- )
      {
        Reference certRef = certPathRef.newChild(Integer.toString(i));
        CertificateValidityType cert = certValidity.get(i);
        updateCodesFromVR(certRef.newChild("validityPeriod"), cert.getValidityPeriodOK(), this);
        updateCodesFromVR(certRef.newChild("chaining"), cert.getChainingOK(), this);
        updateCodesFromSig(certRef, cert.getSignatureOK());
      }
      updateCodesFromVR(certPathRef.newChild("trustAnchor"),
                        xmlReport.getCertificatePathValidity().getPathValidityDetail().getTrustAnchor(),
                        this);
    }
    updateCodesFromVR(certPathRef, xmlReport.getCertificatePathValidity().getPathValiditySummary(), this);
  }

  private void updateCodesFromSig(Reference sigRef, SignatureValidityType svt)
  {
    if (svt.getSignatureAlgorithm() != null && svt.getSignatureAlgorithm().getSuitability() != null)
    {
      updateCodesFromVR(sigRef.newChild("sigAlgo"), svt.getSignatureAlgorithm().getSuitability(), this);
    }
    updateCodesFromVR(sigRef.newChild("math"), svt.getSigMathOK(), this);
  }

  private void updateCodesFromVR(Reference id, VerificationResultType vrt, ReportPart destination)
  {
    destination.updateCodes(ValidationResultMajor.forValue(vrt.getResultMajor()),
                            vrt.getResultMinor(),
                            MinorPriority.IMPORTANT,
                            vrt.getResultMessage() == null ? null : vrt.getResultMessage().getValue(),
                            id);
  }

  private void updateCodesFromVR(Reference id, Result vrt)
  {
    updateCodes(ValidationResultMajor.forDssResult(vrt.getResultMajor(), vrt.getResultMinor()),
                vrt.getResultMinor(),
                MinorPriority.IMPORTANT,
                vrt.getResultMessage() == null ? null : vrt.getResultMessage().getValue(),
                id);
  }

  /**
   * Returns the formatOk report parsed from time stamp verification report which is obtained from another
   * application via eCard API service.
   */
  public FormatOkReport getParsedFormatOk()
  {
    return parsedFormatOk;
  }

  @Override
  public TimeStampValidityType getFormatted()
  {
    return xmlReport;
  }

  @Override
  public Class<TimeStampValidityType> getTargetClass()
  {
    return TimeStampValidityType.class;
  }

}
