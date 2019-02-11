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
package de.bund.bsi.tr_esor.checktool.entry;

import java.io.IOException;

import javax.jws.WebMethod;
import javax.jws.WebParam;
import javax.jws.WebResult;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.xml.bind.JAXBException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.api._1.ArchiveDataRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveDataResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveDeletionRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveEvidenceRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveEvidenceResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveRetrievalRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveRetrievalResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveSubmissionRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveSubmissionResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveUpdateRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveUpdateResponse;
import de.bund.bsi.tr_esor.api._1.ResponseType;
import de.bund.bsi.tr_esor.api._1.S4;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.ValidationScheduler;
import de.bund.bsi.tr_esor.checktool.validation.VerificationResultCreator;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss._1_0.core.schema.VerifyRequest;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Webservice implementing class. Note that only verify operation is supported here.
 *
 * @author TT
 */
@WebService(name = "S4", serviceName = "S4", portName = "S4", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2")
@SOAPBinding(parameterStyle = SOAPBinding.ParameterStyle.BARE)
public class S4VerifyOnly implements S4
{

  private static final String OPERATION_NOT_SUPPORTED_MSG = "only archiveVerify operation is supported by this tool";

  private static final Logger LOG = LoggerFactory.getLogger(S4VerifyOnly.class);

  @Override
  @WebMethod(operationName = "ArchiveSubmission", action = "http://www.bsi.bund.de/tr-esor/ArchiveSubmission")
  @WebResult(name = "ArchiveSubmissionResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters")
  public ArchiveSubmissionResponse archiveSubmission(@WebParam(name = "ArchiveSubmissionRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters") ArchiveSubmissionRequest parameters)
  {
    throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
  }

  @Override
  @WebMethod(operationName = "ArchiveUpdate", action = "http://www.bsi.bund.de/tr-esor/ArchiveUpdate")
  @WebResult(name = "ArchiveUpdateResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters")
  public ArchiveUpdateResponse archiveUpdate(@WebParam(name = "ArchiveUpdateRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters") ArchiveUpdateRequest parameters)
  {
    throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
  }

  @Override
  @WebMethod(operationName = "ArchiveRetrieval", action = "http://www.bsi.bund.de/tr-esor/ArchiveRetrieval")
  @WebResult(name = "ArchiveRetrievalResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters")
  public ArchiveRetrievalResponse archiveRetrieval(@WebParam(name = "ArchiveRetrievalRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters") ArchiveRetrievalRequest parameters)
  {
    throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
  }

  @Override
  @WebMethod(operationName = "ArchiveEvidence", action = "http://www.bsi.bund.de/tr-esor/ArchiveEvidence")
  @WebResult(name = "ArchiveEvidenceResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters")
  public ArchiveEvidenceResponse archiveEvidence(@WebParam(name = "ArchiveEvidenceRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters") ArchiveEvidenceRequest parameters)
  {
    throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
  }

  @Override
  @WebMethod(operationName = "ArchiveDeletion", action = "http://www.bsi.bund.de/tr-esor/ArchiveDeletion")
  @WebResult(name = "ArchiveDeletionResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters")
  public ResponseType archiveDeletion(@WebParam(name = "ArchiveDeletionRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters") ArchiveDeletionRequest parameters)
  {
    throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
  }

  @Override
  @WebMethod(operationName = "ArchiveData", action = "http://www.bsi.bund.de/tr-esor/ArchiveData")
  @WebResult(name = "ArchiveDataResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters")
  public ArchiveDataResponse archiveData(@WebParam(name = "ArchiveDataRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.2", partName = "parameters") ArchiveDataRequest parameters)
  {
    throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
  }

  @Override
  @WebMethod(operationName = "Verify", action = "http://www.bsi.bund.de/tr-esor/Verify")
  @WebResult(name = "VerifyResponse", targetNamespace = "urn:oasis:names:tc:dss:1.0:core:schema", partName = "parameters")
  public ResponseBaseType verify(@WebParam(name = "VerifyRequest", targetNamespace = "urn:oasis:names:tc:dss:1.0:core:schema", partName = "parameters") VerifyRequest parameters)
  {
    ResponseBaseType resp = new ResponseBaseType();
    resp.setRequestID(parameters.getRequestID());

    if (!Configurator.getInstance().isLoaded())
    {
      return setInternalError(resp, "system has not been configured correctly", null);
    }

    ParameterFinder params;
    try
    {
      params = new WSParameterFinder(parameters);
    }
    catch (JAXBException | IllegalArgumentException e)
    {
      LOG.error("parsing failed", e);
      resp.setResult(VerificationResultCreator.createDssResult(ValidationResultMajor.INVALID,
                                                               "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError",
                                                               "parsing of input failed" + e.getMessage()));
      return resp;
    }
    resp.setProfile(params.getProfileName());
    resp.setOptionalOutputs(XmlHelper.FACTORY_DSS.createAnyType());
    try
    {
      InputPreparator input = new InputPreparator(params);
      VerificationReportType report = ValidationScheduler.validate(input.getValidations());
      if (params.getReturnVerificationReport() != null)
      {
        resp.getOptionalOutputs().getAny().add(XmlHelper.toElement(report));
      }
      setWorstResultFromIndividualReports(resp, report);
    }
    catch (JAXBException e)
    {
      setInternalError(resp, "cannot translate report into DOM element", e);
    }
    catch (ReflectiveOperationException | IOException e)
    {
      setInternalError(resp, "unexpected", e);
    }
    return resp;
  }

  private void setWorstResultFromIndividualReports(ResponseBaseType resp, VerificationReportType report)
  {
    if (resp.getResult() == null)
    {
      resp.setResult(VerificationResultCreator.createDssResult(ValidationResultMajor.VALID, null, null));
    }

    ValidationResultMajor vrm = ValidationResultMajor.forValue(resp.getResult().getResultMajor());

    for ( IndividualReportType irt : report.getIndividualReport() )
    {
      ValidationResultMajor newValue = ValidationResultMajor.forValue(irt.getResult().getResultMajor())
                                                            .worse(vrm);
      if (!newValue.equals(vrm))
      {
        resp.setResult(irt.getResult());
        vrm = newValue;
      }
    }
  }

  private ResponseBaseType setInternalError(ResponseBaseType resp, String msg, Exception e)
  {
    LOG.error(msg, e);
    resp.setResult(VerificationResultCreator.createDssResult(ValidationResultMajor.INVALID,
                                                             "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError",
                                                             msg + (e == null ? "" : ": " + e.getMessage())));
    return resp;
  }
}
