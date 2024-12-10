package de.bund.bsi.tr_esor.checktool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import de.bund.bsi.tr_esor.checktool.parser.XaipParser;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.OasisDssResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.signatures.DetachedSignatureValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.signatures.DetachedSignatureValidationContextBuilder;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;

import jakarta.xml.bind.JAXBElement;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.DetailedSignatureReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.TimeStampValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationResultType;


/**
 * Test Helper for signature validation.
 */
public final class SignatureValidationTestHelper
{

    public static final String GENERAL_ERROR = "urn:oasis:names:tc:dss:1.0:resultminor:GeneralError";

    public static final String PARAMETER_ERROR = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError";

    public static final String INCORRECT_SIGNATURE = "urn:oasis:names:tc:dss:1.0:resultminor:invalid:IncorrectSignature";

    public static final String ON_ALL_DOCUMENTS = "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments";


    private SignatureValidationTestHelper()
    {
        // helper class
    }

    public static DetailedSignatureReportType assertContainsDetailedSignatureReportType(IndividualReportType individualReport)
    {
        return assertContainsIndividualReportDetail(individualReport, DetailedSignatureReportType.class);
    }

    public static TimeStampValidityType assertContainsTimeStampValidityType(IndividualReportType individualReport)
    {
        return assertContainsIndividualReportDetail(individualReport, TimeStampValidityType.class);
    }

    public static <T> T assertContainsIndividualReportDetail(IndividualReportType individualReport, Class<T> clazz)
    {
        var details = individualReport.getDetails().getAny();
        assertThat(details).hasSize(1);
        var element = (JAXBElement<?>)details.iterator().next();
        return clazz.cast(element.getValue());
    }

    public static void assertValidResultsInAllIndividualReports(Map<String, IndividualReportType> individualReports)
    {
        for (IndividualReportType individualReport : individualReports.values())
        {
            assertMajorSuccessInIndividualReport(individualReport);
        }
    }

    public static void assertMajorSuccessInIndividualReport(IndividualReportType individualReport)
    {
        assertResult(individualReport.getResult(), OasisDssResultMajor.SUCCESS.toString(), ON_ALL_DOCUMENTS);
        var detailedSignatureReport = assertContainsDetailedSignatureReportType(individualReport);
        assertMajorSuccess(detailedSignatureReport.getFormatOK());
        assertMajorSuccess(detailedSignatureReport.getSignatureOK().getSigMathOK());
    }

    public static void assertRequesterErrorInIndividualReport(IndividualReportType individualReport, String expectedMinor)
    {
        assertResult(individualReport.getResult(), OasisDssResultMajor.REQUESTER_ERROR.toString(), expectedMinor);
        var detailedSignatureReport = assertContainsDetailedSignatureReportType(individualReport);
        assertMajorSuccess(detailedSignatureReport.getFormatOK());
        assertMajorSuccess(detailedSignatureReport.getSignatureOK().getSigMathOK());
    }

    public static void assertInsufficientInformationInIndividualReport(IndividualReportType individualReport, String expectedMinor)
    {
        assertResult(individualReport.getResult(), OasisDssResultMajor.INSUFFICIENT_INFORMATION.toString(), expectedMinor);
        var detailedSignatureReport = assertContainsDetailedSignatureReportType(individualReport);
        assertMajorSuccess(detailedSignatureReport.getFormatOK());
        assertMajorSuccess(detailedSignatureReport.getSignatureOK().getSigMathOK());
    }

    public static void assertMajorSuccess(Result result)
    {
        assertThat(result.getResultMajor()).isEqualTo(OasisDssResultMajor.SUCCESS.toString());
        assertThat(result.getResultMessage()).isNull();
    }

    public static void assertResult(Result result, String major, String minor)
    {
        assertThat(result.getResultMajor()).isEqualTo(major);
        assertThat(result.getResultMinor()).isEqualTo(minor);
        assertThat(result.getResultMessage()).isNull();
    }

    public static void assertResult(Result result, String major, String minor, String message)
    {
        assertThat(result.getResultMajor()).isEqualTo(major);
        assertThat(result.getResultMinor()).isEqualTo(minor);
        assertThat(result.getResultMessage().getValue()).isEqualTo(message);
    }

    public static void assertMajorSuccess(VerificationResultType result)
    {
        assertThat(result.getResultMajor()).isEqualTo(ValidationResultMajor.VALID.toString());
        assertThat(result.getResultMessage()).isNull();
    }

    public static void assertInvalidSigMathResult(VerificationResultType sigMathResult)
    {
        assertThat(sigMathResult.getResultMajor()).isEqualTo(ValidationResultMajor.INVALID.toString());
        assertThat(sigMathResult.getResultMinor()).isEqualTo("HASH_FAILURE");
    }

    public static void assertNoSignatureFound(IndividualReportType individualReport)
    {
        var result = individualReport.getResult();
        assertThat(result.getResultMajor()).isEqualTo(OasisDssResultMajor.SUCCESS.toString());
        assertThat(result.getResultMinor()).isNull();
        assertThat(result.getResultMessage().getValue()).isEqualTo(
            "No inline signature found in data object. Detached signatures might be present.");
        assertThat(individualReport.getDetails()).isNull();
    }

    public static DetachedSignatureValidationContext getValidContext() throws IOException
    {
        try (var ins = TestUtils.class.getResourceAsStream("/xaip/signature/xaip_ok_sig.xml"))
        {
            assertThat(ins).isNotNull();
            var parser = new XaipParser(mock(LXaipReader.class));
            parser.setInput(ins);
            var xas = parser.parse();
            var cred = xas.getXaip().getCredentialsSection().getCredential().get(0);

            return new DetachedSignatureValidationContextBuilder().withXaipSerializer(xas.getSerializer())
                .withProfileName("custom")
                .create(cred);
        }
    }

    public static DetachedSignatureValidationContext getNoSignatureDetachedContext() throws IOException
    {
        try (var ins = TestUtils.class.getResourceAsStream("/xaip/signature/xaip_ok_sig.xml"))
        {
            assertThat(ins).isNotNull();
            var parser = new XaipParser(mock(LXaipReader.class));
            parser.setInput(ins);
            var xas = parser.parse();
            var cred = xas.getXaip().getCredentialsSection().getCredential().get(0);
            cred.getSignatureObject().getBase64Signature().setValue("notASignature".getBytes(StandardCharsets.UTF_8));

            return new DetachedSignatureValidationContextBuilder().withXaipSerializer(xas.getSerializer())
                .withProfileName("custom")
                .create(cred);
        }
    }
}
