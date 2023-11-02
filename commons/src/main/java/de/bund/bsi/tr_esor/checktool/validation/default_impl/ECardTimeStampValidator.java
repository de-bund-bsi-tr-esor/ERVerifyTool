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
import java.net.URL;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.Base64Data;
import oasis.names.tc.dss._1_0.core.schema.DocumentHash;
import oasis.names.tc.dss._1_0.core.schema.DocumentType;
import oasis.names.tc.dss._1_0.core.schema.InputDocuments;
import oasis.names.tc.dss._1_0.core.schema.InternationalStringType;
import oasis.names.tc.dss._1_0.core.schema.SignaturePtr;
import oasis.names.tc.dss._1_0.core.schema.Timestamp;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificatePathValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificatePathValidityVerificationDetailType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificateValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.TimeStampValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.ws.BindingProvider;
import jakarta.xml.ws.WebServiceException;

import org.bouncycastle.tsp.TimeStampToken;
import org.etsi.uri._19102.v1_2.SignatureQualityType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3._2000._09.xmldsig_.DigestMethodType;

import de.bund.bsi.ecard.api._1.ECard;
import de.bund.bsi.ecard.api._1.ECard_Service;
import de.bund.bsi.ecard.api._1.SignatureObject;
import de.bund.bsi.ecard.api._1.VerifyRequest;
import de.bund.bsi.ecard.api._1.VerifyResponse;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.data.TspQuality;
import de.bund.bsi.tr_esor.checktool.entry.ReportDetailLevel;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;


/**
 * Validator for TimeStampToken objects. It issues an eCard VerifyRequest to the configured eCard-compliant
 * web service and embeds the returned TimeStampVerifyReport to the report.
 */
public class ECardTimeStampValidator extends BaseTimeStampValidator
{

  private static final Logger LOG = LoggerFactory.getLogger(ECardTimeStampValidator.class);

  private static final String MINOR_INTERNAL_ERROR = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError";

  private static final String MINOR_PARAMETER_ERROR = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError";

  private static final String MINOR_NOT_SUPPORTED = "http://www.bsi.bund.de/ecard/tr-esor/1.3/resultminor/arl/notSupported";

  private final Supplier<ECard> eCard;

  /**
   * Constructor.
   */
  public ECardTimeStampValidator()
  {
    this.eCard = () -> eCardPort(Configurator.getInstance()
                                             .getVerificationServiceOrNull(ctx.getProfileName()));
  }

  /**
   * for tests only
   */
  public ECardTimeStampValidator(ECard_Service eCardWebService)
  {
    this.eCard = eCardWebService::getECard;
  }

  private static ECard eCardPort(URL url)
  {
    if (url == null)
    {
      return null;
    }
    var port = new ECard_Service(url).getECard();
    ((BindingProvider)port).getRequestContext()
                           .put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, url.toString());
    return port;
  }

  @Override
  public void setContext(ErValidationContext context)
  {
    ctx = context;
  }

  @Override
  public TimeStampReport validateInternal(Reference ref, TimeStampToken toCheck)
  {
    var eCardPort = this.eCard.get();
    if (eCardPort == null)
    {
      return createTimeStampReportForNoValidation(ref, toCheck);
    }
    try
    {
      var request = sourceOfRootHash == null ? verifyRequest(toCheck, ctx)
        : verifyRequest(toCheck, sourceOfRootHash, ctx);
      var response = eCardPort.verifyRequest(request);
      return createIndividualTimeStampReport(response, ref, toCheck);
    }
    catch (WebServiceException e)
    {
      return createReportForWebServiceUnreachable(ref, e, toCheck);
    }
    catch (RuntimeException e)
    {
      throw e;
    }
    catch (Exception e)
    {
      return createReportForRequestFailed(ref, e, toCheck);
    }

  }

  private TimeStampReport createReportForRequestFailed(Reference ref, Exception e, TimeStampToken toCheck)
  {
    LOG.error("eCard request failed", e);
    var timeStampReport = new TimeStampReport(ref);
    timeStampReport.updateCodes(ValidationResultMajor.INDETERMINED,
                                MINOR_INTERNAL_ERROR,
                                MinorPriority.NORMAL,
                                "eCard request failed. Error was: " + e.getMessage(),
                                ref);
    updateFormatOK(ref, toCheck, timeStampReport);
    return timeStampReport;
  }

  private TimeStampReport createReportForWebServiceUnreachable(Reference ref,
                                                               WebServiceException e,
                                                               TimeStampToken toCheck)
  {
    LOG.error("eCard webservice unreachable: {}", e.getMessage());
    var timeStampReport = new TimeStampReport(ref);
    timeStampReport.updateCodes(ValidationResultMajor.INDETERMINED,
                                MINOR_INTERNAL_ERROR,
                                MinorPriority.NORMAL,
                                "eCard webservice is unreachable. Message was: " + e.getMessage(),
                                ref);
    updateFormatOK(ref, toCheck, timeStampReport);
    return timeStampReport;
  }

  private void updateFormatOK(Reference ref, TimeStampToken toCheck, TimeStampReport tsr)
  {
    var formatOk = Optional.ofNullable(tsr.getParsedFormatOk()).orElse(new FormatOkReport(ref));
    checkUnsignedAttributes(toCheck, formatOk);
    tsr.setFormatOk(formatOk);
  }


  private TimeStampReport createIndividualTimeStampReport(VerifyResponse response,
                                                          Reference ref,
                                                          TimeStampToken toCheck)
  {
    var timeStampReport = new TimeStampReport(ref);
    var irt = extractTimestampIndividualReportFromAny(response.getOptionalOutputs(), ref, timeStampReport);
    if (irt == null)
    {
      var minor = response.getResult().getResultMinor() != null ? response.getResult().getResultMinor()
        : MINOR_PARAMETER_ERROR;
      var err = response.getResult().getResultMessage() == null ? ""
        : "Response error was: " + response.getResult().getResultMessage().getValue();
      timeStampReport.updateCodes(ValidationResultMajor.INDETERMINED,
                                  minor,
                                  MinorPriority.NORMAL,
                                  "eCard request failed. " + err,
                                  ref);
    }
    else
    {
      timeStampReport = createTimestampReportFromIndividualReport(irt, ref, timeStampReport);
      checkSignatureQuality(irt, timeStampReport, ref);
    }
    updateFormatOK(ref, toCheck, timeStampReport);
    return timeStampReport;
  }


  private TimeStampReport createTimeStampReportForNoValidation(Reference ref, TimeStampToken toCheck)
  {
    LOG.error("no online validation of time stamp done");

    var timeStampReport = new TimeStampReport(ref);
    timeStampReport.updateCodes(ValidationResultMajor.INDETERMINED,
                                MINOR_INTERNAL_ERROR,
                                MinorPriority.NORMAL,
                                "no online validation of time stamp done",
                                ref);
    updateFormatOK(ref, toCheck, timeStampReport);
    return timeStampReport;
  }

  IndividualReportType extractTimestampIndividualReportFromAny(AnyType any,
                                                               Reference ref,
                                                               TimeStampReport tsr)
  {
    String message;
    if (any == null || any.getAny().size() != 1)
    {
      message = "Illegal eCard response. Did not get exactly one OptionalOutput element as expected.";
    }
    else if (!(any.getAny().get(0) instanceof JAXBElement<?>))
    {
      message = "Illegal eCard response. OptionalOutput element from eCard response could not be parsed.";
    }
    else
    {
      var elem = (JAXBElement<?>)any.getAny().get(0);
      if (elem.getValue() instanceof VerificationReportType)
      {
        return extractTimestampIndividualReportFromVR((VerificationReportType)elem.getValue(), ref, tsr);
      }
      message = "Illegal eCard response. OptionalOutput element is not a VerificationReportType.";
    }
    setParameterError(ref, tsr, message);
    return null;
  }

  private IndividualReportType extractTimestampIndividualReportFromVR(VerificationReportType vr,
                                                                      Reference ref,
                                                                      TimeStampReport tsr)
  {
    String message;
    if (vr.getIndividualReport().size() != 1)
    {
      message = "Illegal eCard response. Did not get exactly one IndividualReport element as expected.";
    }
    else if (vr.getIndividualReport().get(0).getDetails() == null)
    {
      message = "Illegal eCard response. IndividualReport element does not contain details.";
    }
    else
    {
      for ( var irt : vr.getIndividualReport() )
      {
        if (isIndividualReportForTimestamp(irt))
        {
          return irt;
        }
      }
      message = "Illegal eCard response. Details of IndividualReport element does not contain exactly one TimeStampValidityType.";
    }
    setParameterError(ref, tsr, message);
    return null;
  }

  private boolean isIndividualReportForTimestamp(IndividualReportType irt)
  {
    return irt.getDetails()
              .getAny()
              .stream()
              .filter(ir -> ir instanceof JAXBElement<?>)
              .map(ir -> ((JAXBElement<?>)ir).getValue())
              .anyMatch(TimeStampValidityType.class::isInstance);
  }

  TimeStampReport createTimestampReportFromIndividualReport(IndividualReportType irt,
                                                            Reference ref,
                                                            TimeStampReport tsr)
  {
    String message;

    var tvt = irt.getDetails()
                 .getAny()
                 .stream()
                 .filter(ir -> ir instanceof JAXBElement<?>)
                 .map(ir -> ((JAXBElement<?>)ir).getValue())
                 .filter(TimeStampValidityType.class::isInstance)
                 .map(TimeStampValidityType.class::cast)
                 .findFirst();
    if (tvt.isEmpty())
    {
      message = "Illegal eCard response. Details of IndividualReport element does not contain exactly one TimeStampValidityType.";
    }
    else
    {
      return new TimeStampReport(ref, tvt.get(), irt.getResult());
    }

    setParameterError(ref, tsr, message);
    return tsr;
  }

  private void setParameterError(Reference ref, TimeStampReport tsr, String message)
  {
    tsr.updateCodes(ValidationResultMajor.INDETERMINED,
                    MINOR_PARAMETER_ERROR,
                    MinorPriority.NORMAL,
                    message,
                    ref);
  }

  private static VerifyRequest verifyRequest(ErValidationContext ctx) throws JAXBException
  {
    var request = new VerifyRequest();
    request.setRequestID("id#" + System.currentTimeMillis());
    request.setOptionalInputs(returnVerificationReportOI(ctx));
    request.setInputDocuments(new InputDocuments());
    return request;
  }

  private static VerifyRequest verifyRequest(TimeStampToken tsp, ErValidationContext ctx)
    throws IOException, JAXBException
  {
    var request = verifyRequest(ctx);
    var timestamp = new Timestamp();
    timestamp.setRFC3161TimeStampToken(tsp.getEncoded());
    // We pass the timestamp's hash in the verify request in order to verify without the hash's source value
    var documentHash = new DocumentHash();
    documentHash.setDigestValue(tsp.getTimeStampInfo().getMessageImprintDigest());
    var dmt = new DigestMethodType();
    dmt.setAlgorithm(tsp.getTimeStampInfo().getMessageImprintAlgOID().getId());
    documentHash.setDigestMethod(dmt);
    request.getInputDocuments().getDocumentOrTransformedDataOrDocumentHash().add(documentHash);
    var sigObject = new SignatureObject();
    sigObject.setTimestamp(timestamp);
    request.getSignatureObject().add(sigObject);
    return request;
  }

  private static VerifyRequest verifyRequest(TimeStampToken tst,
                                             byte[] sourceOfRootHash,
                                             ErValidationContext ctx)
    throws IOException, JAXBException
  {
    var request = verifyRequest(ctx);
    var tspDoc = document(tst.getEncoded(), "tsp");
    request.getInputDocuments()
           .getDocumentOrTransformedDataOrDocumentHash()
           .add(document(sourceOfRootHash, "signed"));
    request.getInputDocuments().getDocumentOrTransformedDataOrDocumentHash().add(tspDoc);
    var sigObject = new SignatureObject();
    var pointer = new SignaturePtr();
    pointer.setWhichDocument(tspDoc);
    sigObject.setSignaturePtr(pointer);
    request.getSignatureObject().add(sigObject);
    return request;
  }

  private static Object document(byte[] data, String id)
  {
    var doc = new DocumentType();
    doc.setID(id);
    var base64 = new Base64Data();
    base64.setValue(data);
    doc.setBase64Data(base64);
    return doc;
  }

  private static AnyType returnVerificationReportOI(ErValidationContext ctx) throws JAXBException
  {
    var optional = new AnyType();
    var returnVr = ctx.getReturnVerificationReport();
    if (returnVr == null)
    {
      returnVr = XmlHelper.FACTORY_OASIS_VR.createReturnVerificationReport();
      returnVr.setReportDetailLevel(ReportDetailLevel.ALL_DETAILS.toString());
    }
    var element = XmlHelper.toElement(returnVr,
                                      XmlHelper.FACTORY_OASIS_VR.getClass().getPackage().getName(),
                                      null);
    optional.getAny().add(element);
    return optional;
  }

  void checkSignatureQuality(IndividualReportType irt, TimeStampReport tsr, Reference ref)
  {
    var signatureQualityType = getSignatureQuality(irt);
    var requireQualified = Configurator.getInstance().requiresQualifiedTimestamps(ctx.getProfileName());

    if (signatureQualityType == null && !requireQualified)
    {
      tsr.addMessageOnly("The signature quality could not be determined from the eCard response.", ref);
      return;
    }

    if (signatureQualityType == null && requireQualified)
    {
      tsr.updateCodes(ValidationResultMajor.INDETERMINED,
                      MINOR_NOT_SUPPORTED,
                      MinorPriority.NORMAL,
                      "A quality check for a timestamp was requested, but the signature quality could not be determined from the eCard response.",
                      ref);
      return;
    }

    var tspQuality = TspQuality.from(signatureQualityType.getSignatureQualityInformation().get(0));
    enrichTspQualityMessage(tsr, tspQuality);

    if (!tspQuality.isQualified()
        && Configurator.getInstance().requiresQualifiedTimestamps(ctx.getProfileName()))
    {
      generateErrorForLowQuality(tsr, tspQuality, ref);
    }
  }

  private void generateErrorForLowQuality(TimeStampReport tsr, TspQuality quality, Reference ref)
  {
    var certificateValidityTypes = extractCertificateValidityTypes(tsr);
    for ( var cvt : certificateValidityTypes )
    {
      final var resultMajor = ValidationResultMajor.INVALID;
      final var resultMinor = "urn:oasis:names:tc:dss:1.0:detail:IssuerTrust";
      cvt.getChainingOK().setResultMajor(resultMajor.toString());
      cvt.getChainingOK().setResultMinor(resultMinor);
    }
    tsr.updateCodes(ValidationResultMajor.INVALID,
                    MINOR_PARAMETER_ERROR,
                    MinorPriority.NORMAL,
                    "A checked timestamp should be qualified, but the quality of the timestamp was determined as: "
                                          + quality.uri(),
                    ref);
  }

  private void enrichTspQualityMessage(TimeStampReport tsr, TspQuality quality)
  {
    var message = "The quality of the certificate chain for the timestamp was determined as: "
                  + quality.uri();
    var certificateValidityTypes = extractCertificateValidityTypes(tsr);
    for ( var cvt : certificateValidityTypes )
    {
      var oldMessage = cvt.getChainingOK().getResultMessage();
      if (oldMessage != null)
      {
        message = oldMessage.getValue() + "|" + message;
      }
      var internationalString = new InternationalStringType();
      internationalString.setLang("en");
      internationalString.setValue(message);
      cvt.getChainingOK().setResultMessage(internationalString);
    }
  }

  private List<CertificateValidityType> extractCertificateValidityTypes(TimeStampReport tsr)
  {
    return Optional.of(tsr)
                   .map(TimeStampReport::getFormatted)
                   .map(TimeStampValidityType::getCertificatePathValidity)
                   .map(CertificatePathValidityType::getPathValidityDetail)
                   .map(CertificatePathValidityVerificationDetailType::getCertificateValidity)
                   .orElse(List.of());
  }

  private SignatureQualityType getSignatureQuality(IndividualReportType irt)
  {
    for ( var detail : irt.getDetails().getAny() )
    {
      if (detail instanceof JAXBElement)
      {
        var element = (JAXBElement)detail;
        if (SignatureQualityType.class.equals(element.getDeclaredType()))
        {
          return (SignatureQualityType)element.getValue();
        }
      }
      if (detail instanceof SignatureQualityType)
      {
        return (SignatureQualityType)detail;
      }
    }
    return null;
  }

}
