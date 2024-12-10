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
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import de.bund.bsi.tr_esor.checktool.validation.report.BsiResultMajor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.api._1.ArchiveDataRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveDataResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveDeletionRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveDeletionResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveEvidenceRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveEvidenceResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveRetrievalRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveRetrievalResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveSubmissionRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveSubmissionResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveTraceRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveTraceResponse;
import de.bund.bsi.tr_esor.api._1.ArchiveUpdateRequest;
import de.bund.bsi.tr_esor.api._1.ArchiveUpdateResponse;
import de.bund.bsi.tr_esor.api._1.RetrieveInfoRequest;
import de.bund.bsi.tr_esor.api._1.RetrieveInfoResponse;
import de.bund.bsi.tr_esor.api._1.S4;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.validation.ValidationScheduler;
import de.bund.bsi.tr_esor.checktool.validation.VerificationResultCreator;
import de.bund.bsi.tr_esor.checktool.validation.report.OasisDssResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.signatures.ECardResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.signatures.ECardResultMinor;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;

import jakarta.jws.WebMethod;
import jakarta.jws.WebParam;
import jakarta.jws.WebResult;
import jakarta.jws.WebService;
import jakarta.jws.soap.SOAPBinding;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import oasis.names.tc.dss._1_0.core.schema.InternationalStringType;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss._1_0.core.schema.VerifyRequest;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Webservice implementing class. Note that only verify operation is supported here.
 *
 * @author TT
 */
@WebService(name = "S4", serviceName = "S4", portName = "S4", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3")
@SOAPBinding(parameterStyle = SOAPBinding.ParameterStyle.BARE)
@XmlSeeAlso({org.etsi.uri._02918.v1_2.ObjectFactory.class})
public class S4VerifyOnly implements S4
{

    private static final String OPERATION_NOT_SUPPORTED_MSG = "only verify operation is supported by this tool";

    private static final Logger LOG = LoggerFactory.getLogger(S4VerifyOnly.class);

    @Override
    @WebMethod(operationName = "RetrieveInfo", action = "http://www.bsi.bund.de/tr-esor/RetrieveInfoRequest")
    @WebResult(name = "RetrieveInfoResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters")
    public RetrieveInfoResponse retrieveInfo(
        @WebParam(name = "RetrieveInfoRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters") RetrieveInfoRequest parameters)
    {
        throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
    }

    @Override
    @WebMethod(operationName = "ArchiveSubmission", action = "http://www.bsi.bund.de/tr-esor/ArchiveSubmission")
    @WebResult(name = "ArchiveSubmissionResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters")
    public ArchiveSubmissionResponse archiveSubmission(
        @WebParam(name = "ArchiveSubmissionRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters") ArchiveSubmissionRequest parameters)
    {
        throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
    }

    @Override
    @WebMethod(operationName = "ArchiveUpdate", action = "http://www.bsi.bund.de/tr-esor/ArchiveUpdate")
    @WebResult(name = "ArchiveUpdateResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters")
    public ArchiveUpdateResponse archiveUpdate(
        @WebParam(name = "ArchiveUpdateRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters") ArchiveUpdateRequest parameters)
    {
        throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
    }

    @Override
    @WebMethod(operationName = "ArchiveRetrieval", action = "http://www.bsi.bund.de/tr-esor/ArchiveRetrieval")
    @WebResult(name = "ArchiveRetrievalResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters")
    public ArchiveRetrievalResponse archiveRetrieval(
        @WebParam(name = "ArchiveRetrievalRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters") ArchiveRetrievalRequest parameters)
    {
        throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
    }

    @Override
    @WebMethod(operationName = "ArchiveEvidence", action = "http://www.bsi.bund.de/tr-esor/ArchiveEvidence")
    @WebResult(name = "ArchiveEvidenceResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters")
    public ArchiveEvidenceResponse archiveEvidence(
        @WebParam(name = "ArchiveEvidenceRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters") ArchiveEvidenceRequest parameters)
    {
        throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
    }

    @Override
    @WebMethod(operationName = "ArchiveDeletion", action = "http://www.bsi.bund.de/tr-esor/ArchiveDeletion")
    @WebResult(name = "ArchiveDeletionResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters")
    public ArchiveDeletionResponse archiveDeletion(
        @WebParam(name = "ArchiveDeletionRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters") ArchiveDeletionRequest parameters)
    {
        throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
    }

    @Override
    @WebMethod(operationName = "ArchiveData", action = "http://www.bsi.bund.de/tr-esor/ArchiveData")
    @WebResult(name = "ArchiveDataResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters")
    public ArchiveDataResponse archiveData(
        @WebParam(name = "ArchiveDataRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters") ArchiveDataRequest parameters)
    {
        throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
    }

    @Override
    @WebMethod(operationName = "ArchiveTrace", action = "http://www.bsi.bund.de/tr-esor/ArchiveUpdate")
    @WebResult(name = "ArchiveTraceResponse", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters")
    public ArchiveTraceResponse archiveTrace(
        @WebParam(name = "ArchiveTraceRequest", targetNamespace = "http://www.bsi.bund.de/tr-esor/api/1.3", partName = "parameters") ArchiveTraceRequest parameters)
    {
        throw new UnsupportedOperationException(OPERATION_NOT_SUPPORTED_MSG);
    }


    @Override
    @WebMethod(operationName = "Verify", action = "http://www.bsi.bund.de/tr-esor/Verify")
    @WebResult(name = "VerifyResponse", targetNamespace = "urn:oasis:names:tc:dss:1.0:core:schema", partName = "parameters")
    public ResponseBaseType verify(
        @WebParam(name = "VerifyRequest", targetNamespace = "urn:oasis:names:tc:dss:1.0:core:schema", partName = "parameters") VerifyRequest parameters)
    {
        var resp = new ResponseBaseType();
        resp.setRequestID(parameters.getRequestID());

        if (!Configurator.getInstance().isLoaded())
        {
            makeInternalError(resp, "system has not been configured correctly", null);
            return resp;
        }

        ParameterFinder params;
        try
        {
            params = new WSParameterFinder(parameters);
        }
        catch (JAXBException | IllegalArgumentException e)
        {
            LOG.error("parsing failed", e);
            resp.setResult(VerificationResultCreator.createDssResult(OasisDssResultMajor.REQUESTER_ERROR,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError",
                "parsing of input failed" + e.getMessage()));
            return resp;
        }

        resp.setProfile(params.getProfileName());
        resp.setOptionalOutputs(XmlHelper.FACTORY_DSS.createAnyType());
        try
        {
            var input = new InputPreparator(params);
            var report = ValidationScheduler.validate(input.getValidations());
            if (params.getReturnVerificationReport() != null)
            {
                resp.getOptionalOutputs().getAny().add(XmlHelper.toElement(report));
            }
            setWorstResultFromIndividualReports(resp, report);
        }
        catch (JAXBException e)
        {
            makeInternalError(resp, "cannot translate report into DOM element", e);
        }
        catch (ReflectiveOperationException | IOException e)
        {
            makeInternalError(resp, "unexpected", e);
        }
        return resp;
    }

    private void setWorstResultFromIndividualReports(ResponseBaseType resp, VerificationReportType report)
    {
        if (resp.getResult() == null)
        {
            resp.setResult(VerificationResultCreator.createECardResult(ECardResultMajor.OK, null, null));
        }

        var allOasisMajors = allResultMajors(report);

        if (allOasisMajors.stream().allMatch(OasisDssResultMajor.SUCCESS::equals))
        {
            resp.getResult().setResultMajor(BsiResultMajor.OK.getUri());
        }
        else if (allOasisMajors.stream().anyMatch(OasisDssResultMajor.REQUESTER_ERROR::equals))
        {
            resp.getResult().setResultMajor(BsiResultMajor.ERROR.getUri());
            resp.getResult().setResultMinor(extractFirstResultMinorForMajor(report, OasisDssResultMajor.REQUESTER_ERROR));
        }
        else if (allOasisMajors.stream().anyMatch(OasisDssResultMajor.RESPONDER_ERROR::equals))
        {
            resp.getResult().setResultMajor(BsiResultMajor.ERROR.getUri());
            resp.getResult().setResultMinor(extractFirstResultMinorForMajor(report, OasisDssResultMajor.RESPONDER_ERROR));
        }
        else
        {
            resp.getResult().setResultMajor(BsiResultMajor.WARNING.getUri());
            resp.getResult().setResultMinor(extractFirstResultMinorForMajor(report, OasisDssResultMajor.INSUFFICIENT_INFORMATION));
        }

        resp.getResult().setResultMessage(collectResultString(report));
    }

    private InternationalStringType collectResultString(VerificationReportType report)
    {
        var allMessages = report.getIndividualReport()
            .stream()
            .map(irt -> irt.getResult().getResultMessage())
            .filter(Objects::nonNull)
            .map(ist -> ist.getValue())
            .collect(Collectors.toList());
        var internationalString = new InternationalStringType();
        internationalString.setLang("en");
        internationalString.setValue(String.join("|", allMessages));
        return internationalString;
    }

    private List<OasisDssResultMajor> allResultMajors(VerificationReportType report)
    {
        return report.getIndividualReport()
            .stream()
            .map(irt -> OasisDssResultMajor.fromURI(irt.getResult().getResultMajor()))
            .collect(Collectors.toList());
    }

    private String extractFirstResultMinorForMajor(VerificationReportType report, OasisDssResultMajor resultMajor)
    {
        var cause = report.getIndividualReport()
            .stream()
            .filter(irt -> resultMajor.toString().equals(irt.getResult().getResultMajor()))
            .findFirst();
        if (cause.isPresent())
        {
            return cause.get().getResult().getResultMinor();
        }
        else
        {
            return ECardResultMinor.INTERNAL_ERROR;
        }
    }

    private void makeInternalError(ResponseBaseType resp, String msg, Exception e)
    {
        LOG.error(msg, e);
        resp.setResult(VerificationResultCreator.createECardResult(ECardResultMajor.ERROR,
            "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError",
            msg + (e == null ? "" : ": " + e.getMessage())));
    }
}
