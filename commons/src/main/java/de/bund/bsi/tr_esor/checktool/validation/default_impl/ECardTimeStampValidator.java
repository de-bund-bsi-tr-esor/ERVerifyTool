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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.ws.WebServiceException;

import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import de.bund.bsi.ecard.api._1.ECard;
import de.bund.bsi.ecard.api._1.ECard_Service;
import de.bund.bsi.ecard.api._1.SignatureObject;
import de.bund.bsi.ecard.api._1.VerifyRequest;
import de.bund.bsi.tr_esor.checktool.entry.ReportDetailLevel;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss._1_0.core.schema.Timestamp;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.TimeStampValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Validator for TimeStampToken objects. It issues an eCard VerifyRequest to the configured eCard-compliant
 * web service and embeds the returned TimeStampVerifyReport to the report.
 *
 * @author MO
 */
public class ECardTimeStampValidator extends BaseTimeStampValidator
{

  private static final Logger LOG = LoggerFactory.getLogger(ECardTimeStampValidator.class);

  private static final String URL_PARAMETER_NAME = "eCardURL";

  private static final String MINOR_INTERNAL_ERROR = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError";

  private static final String MINOR_PARAMETER_ERROR = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError";

  private URL eCardURL;

  ECard_Service eCardWebService;

  /**
   * Creates a new eCard based time stamp validator.
   *
   * @param parameters
   */
  public ECardTimeStampValidator(Map<String, String> parameters)
  {
    Objects.requireNonNull(parameters);
    if (parameters.isEmpty() || !parameters.containsKey(URL_PARAMETER_NAME))
    {
      throw new IllegalArgumentException("A valid URL to an eCard webservice must be passed as parameter 'eCardURL'");
    }
    try
    {
      eCardURL = new URL(parameters.get(URL_PARAMETER_NAME));
    }
    catch (MalformedURLException e)
    {
      throw new IllegalArgumentException("Malformed URL " + parameters.get(URL_PARAMETER_NAME)
                                         + " given as parameter 'eCardURL'", e);
    }

  }

  @Override
  public void setContext(ErValidationContext context)
  {
    ctx = context;
  }

  @Override
  public TimeStampReport validateInternal(Reference ref, TimeStampToken toCheck)
  {
    TimeStampReport tsr = new TimeStampReport(ref);
    try
    {
      ResponseBaseType response = getECard().verifyRequest(verifyRequestFromTimeStamp(toCheck));
      if ("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok".equals(response.getResult().getResultMajor()))
      {
        tsr = getTSReportFromAny(response.getOptionalOutputs(), ref, tsr);
      }
      else
      {
        String err = response.getResult().getResultMessage() == null ? ""
          : response.getResult().getResultMessage().getValue();
        tsr.updateCodes(ValidationResultMajor.INDETERMINED,
                        response.getResult().getResultMinor(),
                        MinorPriority.NORMAL,
                        "eCard request failed. Response error was: " + err,
                        ref);
      }
    }
    catch (WebServiceException e)
    {
      LOG.error("eCard webservice unreachable", e);
      tsr.updateCodes(ValidationResultMajor.INDETERMINED,
                      MINOR_INTERNAL_ERROR,
                      MinorPriority.NORMAL,
                      "eCard webservice is unreachable. Message was: " + e.getMessage(),
                      ref);
    }
    catch (RuntimeException e)
    {
      throw e;
    }
    catch (Exception e)
    {
      LOG.error("eCard request failed", e);
      tsr.updateCodes(ValidationResultMajor.INDETERMINED,
                      MINOR_INTERNAL_ERROR,
                      MinorPriority.NORMAL,
                      "eCard request failed. Error was: " + e.getMessage(),
                      ref);
    }
    FormatOkReport formatOk = Optional.ofNullable(tsr.getParsedFormatOk()).orElse(new FormatOkReport(ref));
    checkUnsignedAttributes(toCheck, formatOk);
    tsr.setFormatOk(formatOk);
    return tsr;
  }

  TimeStampReport getTSReportFromAny(AnyType any, Reference ref, TimeStampReport tsr)
  {
    String message = null;
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
      JAXBElement<?> elem = (JAXBElement<?>)any.getAny().get(0);
      if (elem.getValue() instanceof VerificationReportType)
      {
        return getTSReportFromVR((VerificationReportType)elem.getValue(), ref, tsr);
      }
      message = "Illegal eCard response. OptionalOutput element is not a VerificationReportType.";
    }
    setParameterError(ref, tsr, message);
    return tsr;
  }

  private TimeStampReport getTSReportFromVR(VerificationReportType vr, Reference ref, TimeStampReport tsr)
  {
    String message = null;
    if (vr.getIndividualReport().size() != 1)
    {
      message = "Illegal eCard response. Did not get exactly one IndividualReport element as expected.";
    }
    else if (vr.getIndividualReport().get(0).getDetails() == null)
    {
      message = "Illegal eCard response. IndividualReport element does not contain details.";
    }
    else if (vr.getIndividualReport().get(0).getDetails().getAny().size() != 1)
    {
      message = "Illegal eCard response. Details of IndividualReport element does not contain exactly one element as expected.";
    }
    else if (!(vr.getIndividualReport().get(0).getDetails().getAny().get(0) instanceof JAXBElement<?>))
    {
      message = "Illegal eCard response. Details of IndividualReport element OptionalOutput element could not be parsed.";
    }
    else
    {
      JAXBElement<?> elem = (JAXBElement<?>)vr.getIndividualReport().get(0).getDetails().getAny().get(0);
      if (elem.getValue() instanceof TimeStampValidityType)
      {
        return new TimeStampReport(ref, (TimeStampValidityType)(elem.getValue()),
                                   vr.getIndividualReport().get(0).getResult());
      }
      message = "Illegal eCard response. Details of IndividualReport element is not a TimeStampValidityType.";
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

  private ECard getECard()
  {
    if (eCardWebService == null)
    {
      eCardWebService = new ECard_Service(eCardURL);
    }
    return eCardWebService.getECard();
  }

  private VerifyRequest verifyRequestFromTimeStamp(TimeStampToken tst) throws IOException, JAXBException
  {
    VerifyRequest request = new VerifyRequest();
    request.setRequestID("id#" + System.currentTimeMillis());
    request.setOptionalInputs(createReturnVerificationReportOI());
    Timestamp timestamp = new Timestamp();
    timestamp.setRFC3161TimeStampToken(tst.getEncoded());
    SignatureObject sigObject = new SignatureObject();
    sigObject.setTimestamp(timestamp);
    request.getSignatureObject().add(sigObject);
    return request;
  }

  private AnyType createReturnVerificationReportOI() throws JAXBException
  {
    AnyType optional = new AnyType();
    ReturnVerificationReport returnVr = ctx.getReturnVerificationReport();
    if (returnVr == null)
    {
      returnVr = XmlHelper.FACTORY_OASIS_VR.createReturnVerificationReport();
      returnVr.setReportDetailLevel(ReportDetailLevel.ALL_DETAILS.toString());
    }
    Element element = XmlHelper.toElement(returnVr,
                                          XmlHelper.FACTORY_OASIS_VR.getClass().getPackage().getName(),
                                          null);
    optional.getAny().add(element);
    return optional;
  }

}
