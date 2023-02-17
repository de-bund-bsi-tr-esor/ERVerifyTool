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
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;

import oasis.names.tc.dss._1_0.core.schema.InternationalStringType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificatePathValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.SignatureValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationResultType;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TSPValidationException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.hash.LocalHashCreator;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.BsiResultMinor;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;
import de.bund.bsi.tr_esor.checktool.validation.signatures.ECardResultMinor;
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
    tsReport.getFormatted().setSignatureOK(validateSigMathOK(toCheck));
    tsReport.updateCodes(ValidationResultMajor.INDETERMINED,
                         null,
                         MinorPriority.NORMAL,
                         "no online validation of time stamp done",
                         ref);
    tsReport.setFormatOk(formatOk);
    return tsReport;
  }

  private SignatureValidityType validateSigMathOK(TimeStampToken toCheck)
  {
    if (sourceOfRootHash == null)
    {
      return signatureValidityWithResult(verificationResultNoDataToCheck());
    }

    try
    {
      if (!checkAtsHashMatches(toCheck))
      {
        return signatureValidityWithResult(verificationResultHashValueMismatch());
      }
    }
    catch (NoSuchAlgorithmException e)
    {
      return signatureValidityWithResult(verificationResultNoSuchAlgorithm(e));
    }

    return doValidateSigMathOK(toCheck);
  }

  private SignatureValidityType doValidateSigMathOK(TimeStampToken toCheck)
  {
    Collection<X509CertificateHolder> tstMatches = toCheck.getCertificates().getMatches(toCheck.getSID());
    X509CertificateHolder holder = tstMatches.iterator().next();
    try
    {
      X509Certificate tstCert = new JcaX509CertificateConverter().getCertificate(holder);
      SignerInformationVerifier siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider())
                                                                              .build(tstCert);
      toCheck.validate(siv);
      return verifyCorrectSigningCertificate(toCheck, tstCert);
    }
    catch (CertificateException ex)
    {
      LOG.error("unable to get the signing certificate for the given time stamp token");
      return signatureValidityWithResult(verificationResultInternalError(ex));
    }
    catch (OperatorCreationException e)
    {
      LOG.error("building the signer information verifier for timestamp verification failed");
      return signatureValidityWithResult(verificationResultInternalError(e));
    }
    catch (TSPValidationException e)
    {
      LOG.warn("validation of given time stamp failed");
      return signatureValidityWithResult(verificationResultSignatureNotOK());
    }
    catch (TSPException tspException)
    {
      return handleTspException(tspException);
    }
  }

  private SignatureValidityType verifyCorrectSigningCertificate(TimeStampToken toCheck,
                                                                X509Certificate tstCert)
  {
    for ( var signer : toCheck.toCMSSignedData().getSignerInfos().getSigners() )
    {
      try
      {
        if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(new BouncyCastleProvider())
                                                                  .build(tstCert)))
        {
          LOG.debug("timestamp signature verified");
          return signatureValidityWithResult(verificationResultOk());
        }
      }
      catch (Exception e)
      {
        LOG.error("building the signer information verifier for timestamp verification failed");
        return signatureValidityWithResult(verificationResultInternalError(e));
      }
    }

    LOG.warn("validation of given time stamp failed");
    return signatureValidityWithResult(verificationResultSignatureNotOK());
  }

  private SignatureValidityType handleTspException(TSPException tspException)
  {
    if (tspException.getCause() instanceof CMSSignerDigestMismatchException)
    {
      return signatureValidityWithResult(verificationResultSignatureNotOK());
    }
    VerificationResultType result = verificationResultInternalError(tspException);
    return signatureValidityWithResult(result);
  }

  private boolean checkAtsHashMatches(TimeStampToken toCheck) throws NoSuchAlgorithmException
  {
    var hashAlgorithm = toCheck.getTimeStampInfo().getHashAlgorithm();
    var hashInTimestamp = toCheck.getTimeStampInfo().getMessageImprintDigest();
    var calculatedHash = new LocalHashCreator().calculateHash(sourceOfRootHash,
                                                              hashAlgorithm.getAlgorithm().getId());
    return Arrays.equals(hashInTimestamp, calculatedHash);
  }

  private SignatureValidityType signatureValidityWithResult(VerificationResultType result)
  {
    var sig = XmlHelper.FACTORY_OASIS_VR.createSignatureValidityType();
    sig.setSigMathOK(result);
    return sig;
  }

  private VerificationResultType verificationResultInternalError(Exception e)
  {
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    result.setResultMajor(ValidationResultMajor.INDETERMINED.toString());
    result.setResultMinor(ECardResultMinor.INTERNAL_ERROR);
    result.setResultMessage(resultMessageEnEn("Error parsing timestamp token: " + e.getMessage()));
    return result;
  }

  private VerificationResultType verificationResultNoDataToCheck()
  {
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    result.setResultMajor(ValidationResultMajor.INDETERMINED.toString());
    result.setResultMinor(ECardResultMinor.DETACHED_SIGNATURE_WITHOUT_E_CONTENT);
    result.setResultMessage(resultMessageEnEn("No data to check the digest in timestamp is present"));
    return result;
  }

  private VerificationResultType verificationResultNoSuchAlgorithm(NoSuchAlgorithmException e)
  {
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    result.setResultMajor(ValidationResultMajor.INDETERMINED.toString());
    result.setResultMinor(ECardResultMinor.HASH_ALGORITHM_NOT_SUPPORTED);
    result.setResultMessage(resultMessageEnEn("Cannot handle hash algorithm: " + e.getMessage()));
    return result;
  }

  private VerificationResultType verificationResultOk()
  {
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    result.setResultMajor(ValidationResultMajor.VALID.toString());
    return result;
  }

  private VerificationResultType verificationResultHashValueMismatch()
  {
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    result.setResultMajor(ValidationResultMajor.INVALID.toString());
    result.setResultMinor(BsiResultMinor.HASH_VALUE_MISMATCH.getUri());
    result.setResultMessage(resultMessageEnEn("The hash value protected by the timestamp does not match the calculated root hash value of the partial hashtree"));
    return result;
  }

  private VerificationResultType verificationResultSignatureNotOK()
  {
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    result.setResultMajor(ValidationResultMajor.INVALID.toString());
    result.setResultMinor(ECardResultMinor.INVALID_SIGNATURE);
    result.setResultMessage(resultMessageEnEn("Validation of the mathematical correctness of the given timestamp failed"));
    return result;
  }

  private InternationalStringType resultMessageEnEn(String content)
  {
    var message = XmlHelper.FACTORY_DSS.createInternationalStringType();
    message.setLang("en-en");
    message.setValue(content);
    return message;
  }


  private CertificatePathValidityType mockCertificatePathValidity()
  {
    var certValidity = XmlHelper.FACTORY_OASIS_VR.createCertificatePathValidityType();
    var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
    result.setResultMajor(ValidationResultMajor.INDETERMINED.toString());
    result.setResultMinor("http://www.bsi.bund.de/ecard/tr-esor/1.3/resultminor/arl/notSupported");
    var message = XmlHelper.FACTORY_DSS.createInternationalStringType();
    message.setLang("en-en");
    message.setValue("Checking certificate paths is not supported by this tool. To check signatures comprehensively, configure an online eCard validation service.");
    result.setResultMessage(message);
    certValidity.setPathValiditySummary(result);
    certValidity.setCertificateIdentifier(XmlHelper.FACTORY_DSIG.createX509IssuerSerialType());
    certValidity.getCertificateIdentifier().setX509IssuerName("unknown");
    certValidity.getCertificateIdentifier().setX509SerialNumber(BigInteger.ZERO);
    return certValidity;
  }
}
