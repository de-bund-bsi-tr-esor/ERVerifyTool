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
package de.bund.bsi.tr_esor.checktool.xml;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.xml.XMLConstants;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3._2000._09.xmldsig_.SignatureValueType;
import org.w3c.dom.Element;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.entry.ReportDetailLevel;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.EvidenceRecordReport;
import de.bund.bsi.tr_esor.checktool.validation.report.OasisDssResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.OutputCreator;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.validation.report.SignatureReportPart;
import de.bund.bsi.tr_esor.checktool.validation.signatures.ECardResultMinor;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.util.JAXBSource;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.DetailedSignatureReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.SignedObjectIdentifierType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.TimeStampValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationResultType;
import oasis.names.tc.saml._2_0.assertion.NameIDType;


/**
 * Collects the validation results into an XML verification report according to schema
 * "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#".
 *
 * @author BVO, HMA, KK, TT
 */
public final class VRCreator
{

    private static final Logger LOG = LoggerFactory.getLogger(VRCreator.class);

    private static Schema schema;

    static
    {
        try
        {
            schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
                .newSchema(VRCreator.class.getResource("/oasis-dssx-1.0-profiles-verification-report-cs1.xsd"));
        }
        catch (SAXException e)
        {
            LOG.error("Failed to load schema", e);
        }
    }

    private VRCreator()
    {
        // static only
    }

    /**
     * Returns a verification report as defined in "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#".
     */
    public static VerificationReportType createReport(List<ReportPart> reportParts, ReturnVerificationReport returnVerificationReport)
    {
        var report = XmlHelper.FACTORY_OASIS_VR.createVerificationReportType();
        var time = XmlHelper.FACTORY_DSS.createVerificationTimeInfoType();
        time.setVerificationTime(XmlHelper.getXMLGregorianCalendar(new Date()));
        report.setVerificationTimeInfo(time);

        var id = XmlHelper.FACTORY_OASIS_VR.createIdentifierType();
        var value = new NameIDType();
        value.setValue(Configurator.getInstance().getVerifierID());
        id.setSAMLv2Identifier(value);
        report.setVerifierIdentity(id);

        reportParts.stream().map(r -> toIndividualReports(r, returnVerificationReport)).forEach(report.getIndividualReport()::addAll);
        validateXml(report);
        return report;
    }

    /**
     * Validates report against schema as demanded by TR-ESOR-ERS-FEIN, p&#46; 29.
     */
    private static void validateXml(VerificationReportType report)
    {
        try
        {
            var validator = schema.newValidator();
            validator.setErrorHandler(new LoggingErrorHandler(LOG));
            var factory = XmlHelper.FACTORY_OASIS_VR;
            var context = JAXBContext.newInstance(factory.getClass().getPackage().getName());
            validator.validate(new JAXBSource(context, factory.createVerificationReport(report)));
        }
        catch (SAXException | JAXBException | IOException e)
        {
            LOG.error("Failed to validate report", e);
        }
    }

    /**
     * Creates XML representation of report.
     *
     * @param report whatever the validator created
     * @param targetClass required class within XML verification report
     */
    @SuppressWarnings("unchecked")
    public static <T> T translate(Object report, Class<T> targetClass)
    {
        if (targetClass.isInstance(report))
        {
            return targetClass.cast(report);
        }
        if (report instanceof OutputCreator && targetClass.isAssignableFrom(((OutputCreator<?>)report).getTargetClass()))
        {
            return ((OutputCreator<T>)report).getFormatted();
        }
        if (report instanceof Reference && targetClass == SignedObjectIdentifierType.class)
        {
            return (T)createIdentifier((Reference)report);
        }
        if (report instanceof ReportPart && !((ReportPart)report).isDetailsPresent())
        {
            return (T)createResultOnly((ReportPart)report);
        }
        throw new IllegalArgumentException("Can not translate " + report.getClass().getName() + " to " + targetClass.getName());
    }

    private static List<IndividualReportType> toIndividualReports(ReportPart report, ReturnVerificationReport returnVR)
    {
        if (report instanceof EvidenceRecordReport)
        {
            return createIndividualReports((EvidenceRecordReport)report, returnVR);
        }
        if (report instanceof SignatureReportPart)
        {
            return createIndividualReports((SignatureReportPart)report, returnVR);
        }
        return List.of(translate(report, IndividualReportType.class));
    }

    private static IndividualReportType createResultOnly(ReportPart report)
    {
        var result = XmlHelper.FACTORY_OASIS_VR.createIndividualReportType();
        result.setSignedObjectIdentifier(createIdentifier(report.getReference()));
        result.setResult(translateResult(report.getOverallResultVerbose()));
        return result;
    }

    private static SignedObjectIdentifierType createIdentifier(Reference ref)
    {
        var identifier = XmlHelper.FACTORY_OASIS_VR.createSignedObjectIdentifierType();
        if (ref.getxPath() != null) // NOPMD
        {
            identifier.setXPath(ref.getxPath());
        }
        else
        {
            identifier.setFieldName(ref.toString());
        }
        return identifier;
    }

    private static List<IndividualReportType> createIndividualReports(EvidenceRecordReport report,
        ReturnVerificationReport returnVerificationReport)
    {
        var result = XmlHelper.FACTORY_OASIS_VR.createIndividualReportType();
        result.setSignedObjectIdentifier(createIdentifier(report.getReference()));
        result.setResult(translateResult(report.getOverallResultVerbose()));
        if (report.isDetailsPresent() && !specifiesNoDetails(returnVerificationReport))
        {
            result.setDetails(XmlHelper.FACTORY_DSS.createAnyType());
            try
            {
                var contextPath = Strings.join(List.of(XmlHelper.FACTORY_ESOR_VR.getClass().getPackage().getName(),
                    XmlHelper.FACTORY_ECARD_EXT.getClass().getPackage().getName()), ':');
                var element =
                    XmlHelper.toElement(report.getFormatted(), contextPath, XmlHelper.FACTORY_ESOR_VR::createEvidenceRecordReport);
                result.getDetails().getAny().add(element);
            }
            catch (JAXBException e)
            {
                LOG.error("Failed to process EvidenceRecordReport XML", e);
            }
        }
        return List.of(result);
    }

    private static List<IndividualReportType> createIndividualReports(SignatureReportPart report,
        ReturnVerificationReport returnVerificationReport)
    {
        var result = new ArrayList<IndividualReportType>();
        if (report.isDetailsPresent() && !specifiesNoDetails(returnVerificationReport))
        {
            var contextPath = Strings.join(List.of(XmlHelper.FACTORY_ESOR_VR.getClass().getPackage().getName(),
                XmlHelper.FACTORY_ECARD_EXT.getClass().getPackage().getName()), ':');
            for (Map.Entry<byte[], Object> entry : report.findSignatureReportDetails().entrySet())
            {
                var individualReport = createIndividualReport(report);
                individualReport.setDetails(XmlHelper.FACTORY_DSS.createAnyType());

                var signatureValueType = new SignatureValueType();
                signatureValueType.setValue(entry.getKey());
                individualReport.getSignedObjectIdentifier().setSignatureValue(signatureValueType);

                var element = toElement(entry.getValue(), contextPath);
                individualReport.getDetails().getAny().add(element);
                result.add(individualReport);
            }
        }
        else
        {
            var individualReport = createIndividualReport(report);
            result.add(individualReport);
        }
        return result;
    }

    private static Element toElement(Object reportType, String contextPath)
    {
        try
        {
            if (reportType instanceof DetailedSignatureReportType)
            {
                return XmlHelper.toElement((DetailedSignatureReportType)reportType,
                    contextPath,
                    XmlHelper.FACTORY_OASIS_VR::createDetailedSignatureReport);
            }
            else if (reportType instanceof TimeStampValidityType)
            {
                return XmlHelper.toElement((TimeStampValidityType)reportType,
                    contextPath,
                    XmlHelper.FACTORY_OASIS_VR::createIndividualTimeStampReport);
            }
        }
        catch (JAXBException e)
        {
            LOG.error("Failed to process signature report XML", e);
        }
        throw new IllegalArgumentException("Given report type must be instance of DetailedSignatureReportType or TimeStampValidityType");
    }

    private static IndividualReportType createIndividualReport(SignatureReportPart report)
    {
        var individualReport = XmlHelper.FACTORY_OASIS_VR.createIndividualReportType();
        individualReport.setSignedObjectIdentifier(createIdentifier(report.getReference()));
        individualReport.setResult(translateResult(report.getOverallResultVerbose()));
        return individualReport;
    }

    private static boolean specifiesNoDetails(ReturnVerificationReport returnVR)
    {
        return ReportDetailLevel.NO_DETAILS.toString()
            .equals(Optional.ofNullable(returnVR).map(ReturnVerificationReport::getReportDetailLevel).orElse(""));
    }

    private static Result translateResult(VerificationResultType input)
    {
        var result = XmlHelper.FACTORY_DSS.createResult();
        if (OasisDssResultMajor.REQUESTER_ERROR.toString().equals(result.getResultMajor())
            || OasisDssResultMajor.SUCCESS.toString()
            .equals(result.getResultMajor())
            || OasisDssResultMajor.RESPONDER_ERROR.toString().equals(result.getResultMajor())
            || OasisDssResultMajor.INSUFFICIENT_INFORMATION.toString().equals(result.getResultMajor()))
        {
            result.setResultMajor(input.getResultMajor());
        }
        else if (ValidationResultMajor.VALID.toString().equals(input.getResultMajor()))
        {
            result.setResultMajor(OasisDssResultMajor.SUCCESS.getUri());
        }
        else if (ValidationResultMajor.INVALID.toString().equals(input.getResultMajor()))
        {
            result.setResultMajor(translateMinorToOasisMajor(input.getResultMinor()).toString());
        }
        else if (ValidationResultMajor.INDETERMINED.toString().equals(input.getResultMajor()))
        {
            result.setResultMajor(OasisDssResultMajor.INSUFFICIENT_INFORMATION.toString());
        }
        else
        {
            result.setResultMajor(OasisDssResultMajor.RESPONDER_ERROR.toString());
        }

        result.setResultMinor(input.getResultMinor());
        result.setResultMessage(input.getResultMessage());
        return result;
    }

    /**
     * This estimates from the ECardResultMinor if the problem is caused by the requester in the sense that a invalid or defective document
     * was provided for the check or by the responder (the eCard implementation), for example a non-reachable OCSP responder. Note that the
     * mapping is designed by explicit BSI request such that only valid signatures lead to success results, while indetermined check results
     * will show insufficient information and invalid signatures will lead to an error.
     */
    public static OasisDssResultMajor translateMinorToOasisMajor(String resultMinor)
    {
        if (resultMinor == null)
        {
            return OasisDssResultMajor.RESPONDER_ERROR;
        }

        switch (resultMinor)
        {
            case ECardResultMinor.INTERNAL_ERROR:
            case ECardResultMinor.NO_PERMISSION:
            case ECardResultMinor.COMMUNICATION_ERROR:
            case ECardResultMinor.SIGNATURE_ALGORITHM_NOT_SUPPORTED:
            case ECardResultMinor.RESOLUTION_OF_OBJECT_REFERENCE_IMPOSSIBLE:
            case ECardResultMinor.TRANSFORMATION_ALGORITHM_NOT_SUPPORTED:
            case ECardResultMinor.HASH_ALGORITHM_NOT_SUPPORTED:
            case ECardResultMinor.UNKNOWN_VIEWER:
            case ECardResultMinor.CERTIFICATE_NOT_FOUND:
            case ECardResultMinor.SIGNATURE_FORMAT_NOT_SUPPORTED:
            case "urn:oasis:names:tc:dss:1.0:resultminor:GeneralError":
                return OasisDssResultMajor.RESPONDER_ERROR;
            case ECardResultMinor.PARAMETER_ERROR:
            case ECardResultMinor.INVALID_SIGNATURE:
            case ECardResultMinor.CERTIFICATE_REVOKED:
            case ECardResultMinor.INVALID_CERTIFICATE_PATH:
            case ECardResultMinor.WRONG_MESSAGE_DIGEST:
            case ECardResultMinor.INVALID_SIGNATURE_FORMAT:
            case ECardResultMinor.HASH_ALGORITHM_NOT_SUITABLE:
            case ECardResultMinor.CERTIFICATE_CHAIN_INTERRUPTED:
            case ECardResultMinor.INVALID_CERTIFICATE_REFERENCE:
            case ECardResultMinor.CERTIFICATE_FORMAT_NOT_CORRECT:
            case ECardResultMinor.CERTIFICATE_PATH_NOT_VALIDATED:
            case ECardResultMinor.CERTIFICATE_STATUS_NOT_CHECKED:
            case ECardResultMinor.SIGNATURE_MANIFEST_NOT_CHECKED:
            case ECardResultMinor.SIGNATURE_MANIFEST_NOT_CORRECT:
            case ECardResultMinor.IMPROPER_REVOCATION_INFORMATION:
            case ECardResultMinor.SIGNATURE_ALGORITHM_NOT_SUITABLE:
            case ECardResultMinor.DETACHED_SIGNATURE_WITHOUT_E_CONTENT:
            case ECardResultMinor.SUITABILITY_OF_ALGORITHMS_NOT_CHECKED:
            case ECardResultMinor.REFERENCED_TIME_NOT_WITHIN_CERTIFICATE_VALIDITY_PERIOD:
            case "urn:oasis:names:tc:dss:1.0:resultminor:invalid:IncorrectSignature":
            case "http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/hashValueMismatch":
            case "http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/invalidFormat":
                return OasisDssResultMajor.REQUESTER_ERROR;
            default:
                return OasisDssResultMajor.RESPONDER_ERROR;
        }
    }

    private static class LoggingErrorHandler implements ErrorHandler
    {

        static final String MSG = "Schema violation in report detected";

        private final Logger log;

        LoggingErrorHandler(Logger log)
        {
            this.log = log;
        }

        @Override
        public void warning(SAXParseException exception) throws SAXException
        {
            log.warn(MSG, exception);
        }

        @Override
        public void error(SAXParseException exception) throws SAXException
        {
            log.error(MSG, exception);
        }

        @Override
        public void fatalError(SAXParseException exception)
        {
            log.error(MSG, exception);
        }

    }
}
