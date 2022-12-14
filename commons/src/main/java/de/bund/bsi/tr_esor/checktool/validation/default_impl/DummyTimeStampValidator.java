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

import java.math.BigInteger;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificatePathValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.SignatureValidityType;

import org.bouncycastle.tsp.TimeStampToken;

import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;


/**
 * Dummy validator for TimeStampToken objects. It just returns "indeterminate" for all elements and does not
 * validate anything.
 *
 * @author MO
 */
public class DummyTimeStampValidator extends BaseTimeStampValidator
{

  @Override
  protected TimeStampReport validateInternal(Reference ref, TimeStampToken toCheck)
  {
    var tsReport = new TimeStampReport(ref);
    var formatOk = new FormatOkReport(ref);
    checkUnsignedAttributes(toCheck, formatOk);
    tsReport.getFormatted().setCertificatePathValidity(mockCertificatePathValidity());
    tsReport.getFormatted().setSignatureOK(mockSignatureValidity());
    tsReport.updateCodes(ValidationResultMajor.INDETERMINED,
                         null,
                         MinorPriority.NORMAL,
                         "no online validation of time stamp done",
                         ref);
    tsReport.setFormatOk(formatOk);
    return tsReport;
  }

  private SignatureValidityType mockSignatureValidity()
  {
    var sig = XmlHelper.FACTORY_OASIS_VR.createSignatureValidityType();
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    result.setResultMajor("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#indetermined");
    result.setResultMinor("http://www.bsi.bund.de/ecard/tr-esor/1.3/resultminor/arl/notSupported");
    var message = XmlHelper.FACTORY_DSS.createInternationalStringType();
    message.setLang("en-en");
    message.setValue("Checking digital signatures is not supported by this tool. To check signatures comprehensively, configure an online eCard validation service.");
    result.setResultMessage(message);
    sig.setSigMathOK(result);
    return sig;
  }


  private CertificatePathValidityType mockCertificatePathValidity()
  {
    var certValidity = XmlHelper.FACTORY_OASIS_VR.createCertificatePathValidityType();
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    result.setResultMajor("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#warning");
    result.setResultMinor("http://www.bsi.bund.de/ecard/tr-esor/1.3/resultminor/arl/notSupported");
    var message = XmlHelper.FACTORY_DSS.createInternationalStringType();
    message.setLang("en-en");
    message.setValue("Checking digital signatures is not supported by this tool. To check signatures comprehensively, configure an online eCard validation service.");
    result.setResultMessage(message);
    certValidity.setPathValiditySummary(result);
    certValidity.setCertificateIdentifier(XmlHelper.FACTORY_DSIG.createX509IssuerSerialType());
    certValidity.getCertificateIdentifier().setX509IssuerName("unknown");
    certValidity.getCertificateIdentifier().setX509SerialNumber(BigInteger.ZERO);
    return certValidity;
  }
}
