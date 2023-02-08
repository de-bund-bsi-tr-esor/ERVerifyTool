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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificatePathValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.SignatureValidityType;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

  private static final Logger LOG = LoggerFactory.getLogger(DummyTimeStampValidator.class);

  @Override
  protected TimeStampReport validateInternal(Reference ref, TimeStampToken toCheck)
  {
    var tsReport = new TimeStampReport(ref);
    var formatOk = new FormatOkReport(ref);
    checkUnsignedAttributes(toCheck, formatOk);
    tsReport.getFormatted().setCertificatePathValidity(mockCertificatePathValidity());
    // tsReport.getFormatted().setSignatureOK(mockSignatureValidity());
    tsReport.getFormatted().setSignatureOK(validateMathSigOK(toCheck));
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
    result.setResultMajor(ValidationResultMajor.INDETERMINED.toString());
    result.setResultMinor("http://www.bsi.bund.de/ecard/tr-esor/1.3/resultminor/arl/notSupported");
    var message = XmlHelper.FACTORY_DSS.createInternationalStringType();
    message.setLang("en-en");
    message.setValue("Checking digital signatures is not supported by this tool. To check signatures comprehensively, configure an online eCard validation service.");
    result.setResultMessage(message);
    sig.setSigMathOK(result);
    return sig;
  }

  private SignatureValidityType validateMathSigOK(TimeStampToken toCheck)
  {
    var sig = XmlHelper.FACTORY_OASIS_VR.createSignatureValidityType();
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    Collection<X509CertificateHolder> tstMatches = toCheck.getCertificates().getMatches(toCheck.getSID());
    X509CertificateHolder holder = tstMatches.iterator().next();
    X509Certificate tstCert = null;
    while (true)
    {
      try
      {
        tstCert = new JcaX509CertificateConverter().getCertificate(holder);
      }
      catch (CertificateException ex)
      {
        LOG.error("unable to get the signing certificate for the given time stamp token");
        result.setResultMajor(ValidationResultMajor.INDETERMINED.toString());
        result.setResultMinor(AlgorithmUsageValidator.ValidationResultMinor.INTERNAL_ERROR.toString());
        break;
      }
      SignerInformationVerifier siv = null;
      try
      {
        siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(tstCert);
      }
      catch (OperatorCreationException e)
      {
        LOG.error("building the signer information verifier for timestamp verification failed");
        result.setResultMajor(ValidationResultMajor.INDETERMINED.toString());
        result.setResultMinor(AlgorithmUsageValidator.ValidationResultMinor.INTERNAL_ERROR.toString());
        break;
      }
      try
      {
        toCheck.validate(siv);

      }
      catch (TSPValidationException e)
      {
        LOG.warn("validation of given time stamp failed");
        result.setResultMajor(ValidationResultMajor.INVALID.toString());
        // result.setResultMinor(AlgorithmUsageValidator.ValidationResultMinor.INTERNAL_ERROR.toString());
        var message = XmlHelper.FACTORY_DSS.createInternationalStringType();
        message.setLang("en-en");
        message.setValue("Validation of the mathematical correctness of the given timestamp failed");
        result.setResultMessage(message);
        break;
      }
      catch (TSPException e1)
      {
        result.setResultMajor(ValidationResultMajor.INDETERMINED.toString());
        result.setResultMinor(AlgorithmUsageValidator.ValidationResultMinor.INTERNAL_ERROR.toString());
        break;
      }
      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
      CMSSignedData signedData = toCheck.toCMSSignedData();
      SignerInformationStore signers = signedData.getSignerInfos();
      Collection<SignerInformation> c = signers.getSigners();
      Iterator<SignerInformation> it = c.iterator();
      boolean validatedOK = false;
      while (it.hasNext())
      {
        try
        {
          SignerInformation signer = it.next();
          if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(tstCert)))
          {
            LOG.info("Signature verified");
            validatedOK = true;
            break;
          }
        }
        catch (Exception e)
        {
          LOG.error("building the signer information verifier for timestamp verification failed");
          result.setResultMajor(ValidationResultMajor.INDETERMINED.toString());
          result.setResultMinor(AlgorithmUsageValidator.ValidationResultMinor.INTERNAL_ERROR.toString());
          break;
        }
      }
      if (validatedOK)
      {
        result.setResultMajor(ValidationResultMajor.VALID.toString());
        break;
      }

      LOG.warn("validation of given time stamp failed");
      result.setResultMajor(ValidationResultMajor.INVALID.toString());
      var message = XmlHelper.FACTORY_DSS.createInternationalStringType();
      message.setLang("en-en");
      message.setValue("Validation of the mathematical correctness of the given timestamp failed");
      result.setResultMessage(message);

      break;
    }
    sig.setSigMathOK(result);
    return sig;
  }


  private CertificatePathValidityType mockCertificatePathValidity()
  {
    var certValidity = XmlHelper.FACTORY_OASIS_VR.createCertificatePathValidityType();
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    result.setResultMajor(ValidationResultMajor.INDETERMINED.toString());
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
