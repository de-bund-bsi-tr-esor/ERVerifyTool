/*- Copyright (c) 2019
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

import static de.bund.bsi.tr_esor.checktool.validation.signatures.ECardResponseUtil.isAcceptableECardResult;
import static de.bund.bsi.tr_esor.checktool.validation.signatures.ECardResponseUtil.isNoSignatureFound;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_DSS;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.Base64Data;
import oasis.names.tc.dss._1_0.core.schema.DocumentType;
import oasis.names.tc.dss._1_0.core.schema.InternationalStringType;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.ws.BindingProvider;
import jakarta.xml.ws.WebServiceException;
import jakarta.xml.ws.soap.SOAPFaultException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import de.bund.bsi.ecard.api._1.ECard;
import de.bund.bsi.ecard.api._1.ECard_Service;
import de.bund.bsi.ecard.api._1.VerifyRequest;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.BaseValidator;
import de.bund.bsi.tr_esor.checktool.validation.report.BsiResultMinor;
import de.bund.bsi.tr_esor.checktool.validation.report.OasisDssResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.OasisDssResultMinor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;
import de.bund.bsi.tr_esor.checktool.validation.report.SignatureReportPart;
import de.bund.bsi.tr_esor.checktool.xml.LXaipDigestMismatchException;
import de.bund.bsi.tr_esor.checktool.xml.LXaipUnprocessableException;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;


/**
 * Base class for signature validation by an eCard service.
 *
 * @param <T> passed to {@link BaseValidator}
 * @param <C> passed to {@link BaseValidator}
 * @author PRE
 */
public abstract class BaseECardSignatureValidator<T, C extends ValidationContext<?>>
  extends BaseValidator<T, C, SignatureReportPart>
{

  private static final Logger LOG = LoggerFactory.getLogger(BaseECardSignatureValidator.class);

  private ECard_Service eCardWebService;

  @Override
  public SignatureReportPart validateInternal(Reference ref, T toCheck)
  {
    SignatureReportPart result = new SignatureReportPart(ref);
    try
    {
      VerifyRequest request = createVerifyRequest(toCheck);
      var eCard = getECard();
      if (eCard == null)
      {
        fillForNoUrl(result, ref);
        return result;
      }

      ResponseBaseType response = eCard.verifyRequest(request);
      if (isNoSignatureFound(response))
      {
        fillForNoSignature(result, ref);
      }
      else if (isAcceptableECardResult(response))
      {
        var resultMessage = generateValidationMessage(response, toCheck);
        fillIn(result, response, resultMessage);
      }
      else
      {
        fillResultForECardError(result, response, ref);
      }
    }
    catch (SOAPFaultException e)
    {
      LOG.error("Unexpected eCard response", e);
      fillInIndetermined(result, ref, "eCard responded unexpectedly. Message was: " + e.getMessage());
    }
    catch (WebServiceException e)
    {
      LOG.error("eCard webservice unreachable", e);
      fillInIndetermined(result, ref, "eCard webservice is unreachable. Message was: " + e.getMessage());
    }
    catch (JAXBException e)
    {
      LOG.error("Cannot construct eCard request", e);
      fillInIndetermined(result, ref, "eCard request failed. Error was: " + e.getMessage());
    }
    catch (IOException e)
    {
      LOG.error("Cannot read data from XAIP", e);
      fillInIndetermined(result, ref, "eCard request failed. Error was: " + e.getMessage());
    }
    catch (LXaipDigestMismatchException e)
    {
      LOG.error("Digest miss match in LXaip", e);
      fillInInvalidLXaipChecksum(result, ref, "Digest mismatch in LXaip: " + e.getMessage());
    }
    catch (LXaipUnprocessableException e)
    {
      LOG.error("LXaip Unprocessable", e);
      fillInIndetermined(result, ref, "Unprocessable LXaip: " + e.getMessage());
    }
    return result;
  }

  protected abstract VerifyRequest createVerifyRequest(T toCheck) throws JAXBException, IOException;

  protected DocumentType createBase64Document(String id, byte[] content)
  {
    Base64Data data = FACTORY_DSS.createBase64Data();
    data.setValue(content);
    DocumentType doc = FACTORY_DSS.createDocumentType();
    doc.setBase64Data(data);
    doc.setID(id);
    return doc;
  }

  protected AnyType createReturnVerificationReportOI() throws JAXBException
  {
    Element element = XmlHelper.toElement(ctx.getReturnVerificationReport(),
                                          XmlHelper.FACTORY_OASIS_VR.getClass().getPackage().getName(),
                                          null);
    AnyType optional = new AnyType();
    optional.getAny().add(element);
    return optional;
  }

  protected ECard getECard()
  {
    if (!Configurator.getInstance().hasVerificationService(ctx.getProfileName()))
    {
      return null;
    }

    var eCardURL = Configurator.getInstance().getVerificationServiceOrFail(ctx.getProfileName());
    if (eCardWebService == null)
    {
      LOG.info("init eCard service ({})", eCardURL);
      eCardWebService = new ECard_Service(eCardURL);
    }
    var port = eCardWebService.getECard();
    // change the WSDL baked in address to the actual endpoint address
    ((BindingProvider)port).getRequestContext()
                           .put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, eCardURL.toString());
    return port;
  }

  private static void fillForNoSignature(SignatureReportPart result, Reference ref)
  {
    var message = "No signature found in data object.";
    result.addMessageOnly(message, ref);
    result.setVr(singleMessageVerificationReport(OasisDssResultMajor.REQUESTER_ERROR,
                                                 OasisDssResultMinor.ERROR_REQUEST_NOT_SUPPORTED,
                                                 message));
  }

  private static void fillForNoUrl(SignatureReportPart result, Reference ref)
  {
    var message = "No online validation of a potential signature was possible as no validation service is configured in the active profile.";
    result.updateCodes(ValidationResultMajor.INDETERMINED,
                       ECardResultMinor.COMMUNICATION_ERROR,
                       MinorPriority.NORMAL,
                       message,
                       ref);
    result.setVr(singleMessageVerificationReport(OasisDssResultMajor.INSUFFICIENT_INFORMATION,
                                                 OasisDssResultMinor.ERROR_REQUEST_NOT_SUPPORTED,
                                                 message));
  }

  private static void fillInInvalidLXaipChecksum(SignatureReportPart result, Reference ref, String message)
  {
    result.updateCodes(ValidationResultMajor.INVALID,
                       BsiResultMinor.HASH_VALUE_MISMATCH.getUri(),
                       MinorPriority.NORMAL,
                       message,
                       ref);
    result.setVr(singleMessageVerificationReport(OasisDssResultMajor.INSUFFICIENT_INFORMATION,
                                                 OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR,
                                                 message));
  }

  private static void fillInIndetermined(SignatureReportPart result, Reference ref, String message)
  {
    result.updateCodes(ValidationResultMajor.INDETERMINED,
                       ECardResultMinor.INTERNAL_ERROR,
                       MinorPriority.NORMAL,
                       message,
                       ref);
    result.setVr(singleMessageVerificationReport(OasisDssResultMajor.RESPONDER_ERROR,
                                                 OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR,
                                                 message));
  }

  private static VerificationReportType singleMessageVerificationReport(OasisDssResultMajor major,
                                                                        OasisDssResultMinor minor,
                                                                        String message)
  {
    IndividualReportType individualReport = new IndividualReportType();
    Result resultCase = new Result();
    individualReport.setResult(resultCase);
    resultCase.setResultMajor(major.toString());
    resultCase.setResultMinor(minor.toString());
    InternationalStringType resultMessage = new InternationalStringType();
    resultMessage.setLang("en");
    resultMessage.setValue(message);

    resultCase.setResultMessage(resultMessage);
    VerificationReportType verificationReport = FACTORY_OASIS_VR.createVerificationReportType();
    verificationReport.getIndividualReport().add(individualReport);
    return verificationReport;
  }

  private static void fillResultForECardError(SignatureReportPart result,
                                              ResponseBaseType response,
                                              Reference ref)
  {
    String resultMessage = null;
    if (response.getResult().getResultMessage() != null)
    {
      resultMessage = response.getResult().getResultMessage().getValue();
    }

    String message = String.format("eCard request failed. Result in eCard response was: major: %s, minor: %s, message: %s",
                                   response.getResult().getResultMajor(),
                                   response.getResult().getResultMinor(),
                                   resultMessage);

    result.updateCodes(ValidationResultMajor.INDETERMINED,
                       response.getResult().getResultMinor(),
                       MinorPriority.IMPORTANT,
                       message,
                       ref);

    result.setVr(singleMessageVerificationReport(OasisDssResultMajor.RESPONDER_ERROR,
                                                 OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR,
                                                 message));
  }

  @SuppressWarnings("PMD.DataflowAnomalyAnalysis")
  String generateValidationMessage(ResponseBaseType response, T toCheck)
  {
    if (response == null)
    {
      return "Illegal eCard response. No optional outputs were received from the eCardService.";
    }

    var any = response.getOptionalOutputs().getAny();
    if (any.isEmpty())
    {
      return "Illegal eCard response. The optional outputs section that was received from the eCardService is empty.";
    }

    List<JAXBElement<?>> elements = any.stream()
                                       .filter(e -> e instanceof JAXBElement<?>)
                                       .map(e -> (JAXBElement<?>)e)
                                       .collect(Collectors.toList());
    if (elements.isEmpty())
    {
      return "Illegal eCard response. Could not parse the existing optional outputs from the eCard response.";
    }

    Optional<JAXBElement<?>> vrElement = elements.stream()
                                                 .filter(x -> x.getDeclaredType()
                                                               .equals(VerificationReportType.class))
                                                 .findAny();
    if (vrElement.isEmpty())
    {
      return "Illegal eCard response. OptionalOutput element is not a VerificationReportType.";
    }

    var verificationReport = (VerificationReportType)vrElement.get().getValue();
    if (isRestrictedValidation(verificationReport, toCheck))
    {
      return "Only Base64 encoded signatures can be validated via S4VerifyOnly";
    }

    return null;
  }

  static void fillIn(SignatureReportPart report, ResponseBaseType response, String resultMessage)
  {
    if (resultMessage == null)
    {
      var verificationReport = (VerificationReportType)response.getOptionalOutputs()
                                                               .getAny()
                                                               .stream()
                                                               .filter(e -> e instanceof JAXBElement<?>)
                                                               .map(e -> (JAXBElement<?>)e)
                                                               .filter(x -> x.getDeclaredType()
                                                                             .equals(VerificationReportType.class))
                                                               .findAny()
                                                               .map(JAXBElement::getValue)
                                                               .orElseThrow();
      report.setVr(verificationReport);
      report.updateCodes(verificationResultMajor(response),
                         verificationResultMinor(verificationReport),
                         MinorPriority.NORMAL,
                         null,
                         report.getReference());
    }
    else
    {
      report.updateCodes(ValidationResultMajor.INDETERMINED,
                         ECardResultMinor.PARAMETER_ERROR,
                         MinorPriority.NORMAL,
                         resultMessage,
                         report.getReference());
    }
  }

  /**
   * @param verificationReport {@link ResponseBaseType} to check existing validation result
   * @param toCheck validated object
   * @return <code>true</code> if validation is restricted in certain cases
   */
  protected abstract boolean isRestrictedValidation(VerificationReportType verificationReport, T toCheck);

  private static String verificationResultMinor(VerificationReportType verificationReport)
  {
    var individualReports = verificationReport.getIndividualReport();
    if (individualReports == null || individualReports.isEmpty())
    {
      return null;
    }
    var result = individualReports.get(0).getResult();
    if (result == null)
    {
      return null;
    }
    return result.getResultMinor();
  }

  private static ValidationResultMajor verificationResultMajor(ResponseBaseType response)
  {
    return response.getResult().getResultMajor().equals(ECardResultMajor.ERROR)
      ? ValidationResultMajor.INVALID : ValidationResultMajor.VALID;
  }
}
