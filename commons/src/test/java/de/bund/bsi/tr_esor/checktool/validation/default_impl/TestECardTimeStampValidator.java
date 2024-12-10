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


import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_DSS;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ECARD;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collection;
import java.util.Collections;
import java.util.function.Supplier;

import javax.xml.transform.stream.StreamSource;

import jakarta.xml.bind.JAXBElement;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificatePathValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificatePathValidityVerificationDetailType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificateStatusType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.CertificateValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.DetailedSignatureReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.TimeStampValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.etsi.uri._19102.v1_2.SignatureQualityType;
import org.junit.Test;

import de.bund.bsi.ecard.api._1.ECard;
import de.bund.bsi.ecard.api._1.ECard_Service;
import de.bund.bsi.ecard.api._1.VerifyResponse;
import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;

import jakarta.xml.bind.JAXBException;
import jakarta.xml.ws.WebServiceException;
import oasis.names.tc.dss._1_0.core.schema.AnyType;
import org.w3._2000._09.xmldsig_.X509IssuerSerialType;

/**
 * Offline checks for ECardTimeStampValidator.
 */
public class TestECardTimeStampValidator
{

    /**
     * Tests for errors with illegal URL values.
     */
    @Test
    public void testInvalidURL() throws Exception
    {
        var sut = sut("invalid");
        sut.setContext(new ErValidationContext(new Reference("dummy"), "", ""));
        var result = sut.validate(new Reference("dummy"), someTimeStampToken());

        assertThat(result.getSummarizedMessage(), containsString("no online validation of time stamp done"));
    }

    /**
     * Tests for unreachable eCard responder.
     */
    @Test
    public void testUnreachableResponder() throws Exception
    {
        var sut = sut("http://unreachable:8080/eCard/eCard?wsdl");
        sut.setContext(new ErValidationContext(new Reference("dummy"), "", ""));
        ReportPart result = sut.validate(new Reference("dummy"), someTimeStampToken());

        assertThat(result.getSummarizedMessage(), containsString("no online validation of time stamp done"));
    }

    @Test
    public void handlesVrWithSuccess() throws Exception
    {
        var sut = sut("http://ignored");
        var ref = new Reference("tsp");
        var irt = sut.extractTimestampIndividualReportFromAny(anyFromVR("/vr/success.xml"), ref, new TimeStampReport(ref));
        var report = sut.createTimestampReportFromIndividualReport(irt, ref, new TimeStampReport(ref));
        assertThat(report.getOverallResult().getResultMajor(), endsWith(":valid"));
        assertThat(report.getSummarizedMessage(), is(emptyOrNullString()));
    }

    @Test
    public void handlesMissingQualityStatement() throws Exception
    {
        TimeStampReport tsr = timeStampReportFromXMLWithProfile("custom");
        assertThat(tsr.getOverallResult().getResultMajor(), endsWith(":valid"));
        assertThat(tsr.getSummarizedMessage(), containsString("The signature quality could not be determined from the eCard response."));
    }

    @Test
    public void requiresMissingQualityStatementForQualifiedTsp() throws Exception
    {
        TimeStampReport tsr = timeStampReportFromXMLWithProfile("TR-ESOR");
        assertThat(tsr.getOverallResult().getResultMajor(), endsWith(":indetermined"));
        assertThat(tsr.getSummarizedMessage(),
            containsString(
                "A quality check for a timestamp was requested, but the signature quality could not be determined from the eCard response."));
    }

    private TimeStampReport timeStampReportFromXMLWithProfile(String profileName) throws Exception
    {
        TestUtils.loadDefaultConfig();
        var sut = sut("http://ignored");
        var ref = new Reference("tsp");
        sut.setContext(new ErValidationContext(ref, "", profileName));
        var tsr = new TimeStampReport(ref);
        var irt = sut.extractTimestampIndividualReportFromAny(anyFromVR("/vr/success.xml"), ref, tsr);
        tsr = sut.createTimestampReportFromIndividualReport(irt, ref, tsr);
        sut.checkSignatureQuality(irt, tsr, ref);
        return tsr;
    }

    @Test
    public void handlesQualityStatement() throws Exception
    {
        TimeStampReport tsr = timeStampReportFromXMLwithQuality("http://val-service/val/QTST_EUMS_TL");
        assertThat(tsr.getOverallResult().getResultMajor(), endsWith(":valid"));
        assertThat(extractChainingOkMessage(tsr),
            containsString("The quality of the certificate chain for the timestamp was determined as: http://val-service/val/QTST_EUMS_TL"));
        assertThat(tsr.getSummarizedMessage(), is(emptyOrNullString()));
    }

    @Test
    public void deniesLowQualityStatement() throws Exception
    {
        TimeStampReport tsr = timeStampReportFromXMLwithQuality("http://val-service/val/DTST");
        assertThat(tsr.getOverallResult().getResultMajor(), endsWith(":invalid"));
        assertThat(extractChainingOkMessage(tsr),
            containsString("The quality of the certificate chain for the timestamp was determined as: http://val-service/val/DTST"));
        assertThat(tsr.getSummarizedMessage(),
            is("A checked timestamp should be qualified, but the quality of the timestamp was determined as: http://val-service/val/DTST"));
    }

    @Test
    public void detailMissingInIRT() throws Exception
    {
        var sut = sut("http://ignored");
        var ref = new Reference("tsp");
        var tsr = new TimeStampReport(ref);
        var irt = sut.extractTimestampIndividualReportFromAny(anyFromVR("/vr/success.xml"), ref, tsr);
        irt.setDetails(null);

        var result = sut.findCertificatePathValidity(irt);

        assertThat(result, nullValue());
    }

    @Test
    public void detailIsEmpty() throws Exception
    {
        var sut = sut("http://ignored");
        var ref = new Reference("tsp");
        var tsr = new TimeStampReport(ref);
        var irt = sut.extractTimestampIndividualReportFromAny(anyFromVR("/vr/success.xml"), ref, tsr);
        irt.getDetails().getAny().clear();

        var result = sut.findCertificatePathValidity(irt);

        assertThat(result, nullValue());
    }

    @Test
    public void reportTypeNotTimeStampValidityType() throws Exception
    {
        var sut = sut("http://ignored");
        var ref = new Reference("tsp");
        var tsr = new TimeStampReport(ref);
        var irt = sut.extractTimestampIndividualReportFromAny(anyFromVR("/vr/success.xml"), ref, tsr);
        var jaxbElement = mock(JAXBElement.class);
        when(jaxbElement.getValue()).thenReturn(new DetailedSignatureReportType());
        irt.getDetails().getAny().set(0, jaxbElement);

        var result = sut.findCertificatePathValidity(irt);

        assertThat(result, nullValue());
    }

    @Test
    public void certificatePathValidityDetailFound() throws Exception
    {
        var sut = sut("http://ignored");
        var ref = new Reference("tsp");
        var tsr = new TimeStampReport(ref);
        var irt = sut.extractTimestampIndividualReportFromAny(anyFromVR("/vr/success.xml"), ref, tsr);

        var result = sut.findCertificatePathValidity(irt);

        var certificatePathValidity = ((TimeStampValidityType) ((JAXBElement<?>)
                irt.getDetails().getAny().get(0)).getValue()).getCertificatePathValidity();
        assertThat(result, is(certificatePathValidity));
    }

    @Test
    public void pathValidityDetailIsntFound() throws Exception
    {
        var sut = sut("http://ignored");
        var certificatePathValidity = new CertificatePathValidityType();
        var tsp = createTimeStampTokenMock(null);

        sut.fillCertificatePathValidity(certificatePathValidity, tsp);

        assertThat(certificatePathValidity.getPathValidityDetail(), nullValue());
    }

    @Test
    public void revocationEvidenceExists() throws Exception
    {
        var sut = sut("http://ignored");
        var certificatePathValidity = createCertificatePathValidityType();
        var revocationEvidence = new CertificateStatusType.RevocationEvidence();
        certificatePathValidity.getPathValidityDetail().getCertificateValidity().get(0).getCertificateStatus().setRevocationEvidence(revocationEvidence);
        var tsp = createTimeStampTokenMock(null);

        sut.fillCertificatePathValidity(certificatePathValidity, tsp);

        assertThat(certificatePathValidity.getPathValidityDetail().getCertificateValidity().get(0).getCertificateStatus().getRevocationEvidence(), is(revocationEvidence));
    }

    @Test
    public void noCertificatesFound() throws Exception
    {
        var sut = sut("http://ignored");
        var certificatePathValidity = createCertificatePathValidityType();
        var certificateIdentifier = mock(X509IssuerSerialType.class);
        when(certificateIdentifier.getX509SerialNumber()).thenReturn(new BigInteger("1"));
        certificatePathValidity.getPathValidityDetail().getCertificateValidity().get(0).setCertificateIdentifier(certificateIdentifier);
        var tsp = createTimeStampTokenMock(Collections.emptyList());

        sut.fillCertificatePathValidity(certificatePathValidity, tsp);

        assertThat(certificatePathValidity.getPathValidityDetail().getCertificateValidity().get(0).getCertificateStatus().getRevocationEvidence(), nullValue());
    }

    @Test
    public void updateCertificatePathValidityFail() throws Exception
    {
        var sut = sut("http://ignored");
        var certPathVal = new CertificatePathValidityType();
        var ref = new Reference("tsp");
        var tsr = new TimeStampReport(ref);
        var irt = sut.extractTimestampIndividualReportFromAny(anyFromVR("/vr/success.xml"), ref, tsr);
        var jaxbElement = mock(JAXBElement.class);
        when(jaxbElement.getValue()).thenReturn(new DetailedSignatureReportType());
        irt.getDetails().getAny().set(0, jaxbElement);

        sut.addUpdatedCertificatePathValidity(irt, certPathVal);

        var certificatePathValidity = ((DetailedSignatureReportType) ((JAXBElement<?>)
                irt.getDetails().getAny().get(0)).getValue()).getCertificatePathValidity();
        assertThat(certificatePathValidity, not(certPathVal));
    }

    @Test
    public void updateCertificatePathSuccess() throws Exception
    {
        var sut = sut("http://ignored");
        var certPathVal = new CertificatePathValidityType();
        var ref = new Reference("tsp");
        var tsr = new TimeStampReport(ref);
        var irt = sut.extractTimestampIndividualReportFromAny(anyFromVR("/vr/success.xml"), ref, tsr);

        sut.addUpdatedCertificatePathValidity(irt, certPathVal);

        var certificatePathValidity = ((TimeStampValidityType) ((JAXBElement<?>)
                irt.getDetails().getAny().get(0)).getValue()).getCertificatePathValidity();
        assertThat(certificatePathValidity, is(certificatePathValidity));
    }

    static String extractChainingOkMessage(TimeStampReport tsr)
    {
        return tsr.getFormatted()
            .getCertificatePathValidity()
            .getPathValidityDetail()
            .getCertificateValidity()
            .get(0)
            .getChainingOK()
            .getResultMessage()
            .getValue();
    }

    private CertificatePathValidityType createCertificatePathValidityType()
    {
        var certificatePathValidity = new CertificatePathValidityType();
        certificatePathValidity.setPathValidityDetail(new CertificatePathValidityVerificationDetailType());
        var certificateValidityType = new CertificateValidityType();
        var certificateStatus = new CertificateStatusType();
        certificateValidityType.setCertificateStatus(certificateStatus);
        certificatePathValidity.getPathValidityDetail().getCertificateValidity().add(certificateValidityType);
        return certificatePathValidity;
    }
    private TimeStampToken createTimeStampTokenMock(Collection<X509CertificateHolder> certificateHolder)
    {
        var tsp = mock(TimeStampToken.class);
        var certHolder = mock(Store.class);
        when(tsp.getCertificates()).thenReturn(certHolder);
        when(tsp.getCertificates().getMatches(null)).thenReturn(certificateHolder);
        return tsp;
    }

    private TimeStampReport timeStampReportFromXMLwithQuality(String quality) throws Exception
    {
        TestUtils.loadDefaultConfig();
        var sut = sut("http://ignored");
        var ref = new Reference("tsp");
        sut.setContext(new ErValidationContext(ref, "", "TR-ESOR"));
        var tsr = new TimeStampReport(ref);
        var any = anyFromVR("/vr/success.xml");
        var irt = sut.extractTimestampIndividualReportFromAny(any, ref, tsr);
        var signatureQuality = new SignatureQualityType();
        signatureQuality.getSignatureQualityInformation().add(quality);
        irt.getDetails().getAny().add(signatureQuality);
        tsr = sut.createTimestampReportFromIndividualReport(irt, ref, tsr);
        sut.checkSignatureQuality(irt, tsr, ref);
        return tsr;
    }

    @Test
    public void handlesVrWithInsufficientInformation() throws Exception
    {
        var sut = sut("http://ignored");
        var ref = new Reference("tsp");
        var report = new TimeStampReport(ref);
        var irt = sut.extractTimestampIndividualReportFromAny(anyFromVR("/vr/insufficient_information.xml"), ref, report);
        report = sut.createTimestampReportFromIndividualReport(irt, ref, report);
        assertThat(report.getOverallResult().getResultMajor(), endsWith(":indetermined"));
        assertThat(report.getSummarizedMessage(), containsString("detached_content_file_missing"));
    }

    @Test
    public void handlesVrWithResponderError() throws Exception
    {
        var sut = sut("http://ignored");
        var ref = new Reference("tsp");
        var report = new TimeStampReport(ref);
        var irt = sut.extractTimestampIndividualReportFromAny(anyFromVR("/vr/responder_error.xml"), ref, report);
        report = sut.createTimestampReportFromIndividualReport(irt, ref, report);
        assertThat(report.getOverallResult().getResultMajor(), endsWith(":invalid"));
        assertThat(report.getSummarizedMessage(), is(emptyOrNullString()));
    }

    private static AnyType anyFromVR(String file) throws IOException, JAXBException
    {
        try (var ins = TestECardTimeStampValidator.class.getResourceAsStream(file))
        {
            var vr =
                XmlHelper.parse(new StreamSource(ins), VerificationReportType.class, FACTORY_OASIS_VR.getClass().getPackage().getName());
            var any = FACTORY_DSS.createAnyType();
            any.getAny().add(FACTORY_OASIS_VR.createVerificationReport(vr));
            return any;
        }
    }

    /**
     * Asserts that error codes are mapped correctly when eCard reports an error.
     */
    @Test
    public void reportECardError() throws Exception
    {
        var ref = new Reference("dummy");
        var errMsg = "something went wrong";
        var tst = someTimeStampToken();
        var ecard = mock(ECard.class);
        var sut = sut(ecard);
        sut.setContext(new ErValidationContext(ref, "", ""));

        var response = FACTORY_ECARD.createVerifyResponse();
        var result = FACTORY_DSS.createResult();
        response.setResult(result);

        result.setResultMajor("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error");
        result.setResultMinor("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError");
        var message = FACTORY_DSS.createInternationalStringType();
        message.setLang("en");
        message.setValue(errMsg);
        result.setResultMessage(message);

        when(ecard.verifyRequest(any())).thenReturn(response);
        var report = sut.validate(ref, tst);

        assertThat(report.getOverallResult().getResultMajor(), is("urn:oasis:names:tc:dss:1.0:detail:indetermined"));
        assertThat(report.getOverallResult().getResultMinor(),
            is("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError"));
        assertThat(report.getOverallResult().getResultMessage().getValue(),
            containsString("eCard request failed. Response error was: " + errMsg));
    }

    /**
     * Asserts that a meaningful report is returned when the eCard service is unreachable.
     */
    @Test
    public void reportUnreachable() throws Exception
    {
        var ref = new Reference("dummy");
        var errMsg = "something went wrong";
        var tst = someTimeStampToken();
        var ecard = mock(ECard.class);
        var sut = sut(ecard);
        sut.setContext(new ErValidationContext(ref, "", ""));

        when(ecard.verifyRequest(any())).thenThrow(new WebServiceException(errMsg));
        var report = sut.validate(ref, tst);

        assertThat(report.getOverallResult().getResultMajor(), endsWith(":indetermined"));
        assertThat(report.getOverallResult().getResultMinor(), endsWith("#internalError"));
        assertThat(report.getOverallResult().getResultMessage().getValue(), is("eCard webservice is unreachable. Message was: " + errMsg));
    }

    /**
     * Asserts that the validator reports meaningful messages in case that the used eCard does not respond properly.
     */
    @Test
    @SuppressWarnings("checkstyle:LeftCurly")
    public void reportIllegalECardResponses() throws Exception
    {
        var elementWithWrongType = FACTORY_OASIS_VR.createDetailedSignatureReport(new DetailedSignatureReportType());

        reportIllegalOptionalOutput("Did not get exactly one OptionalOutput element as expected.", FACTORY_DSS::createAnyType);
        reportIllegalOptionalOutput("OptionalOutput element from eCard response could not be parsed.", //
            () -> {
                var any = FACTORY_DSS.createAnyType();
                any.getAny().add("cannotBeParsed");
                return any;
            });
        reportIllegalOptionalOutput("OptionalOutput element is not a VerificationReportType.", //
            () -> {
                var any = FACTORY_DSS.createAnyType();
                any.getAny().add(elementWithWrongType);
                return any;
            });
        reportIllegalVerificationReport("Did not get exactly one IndividualReport element as expected.",
            FACTORY_OASIS_VR::createVerificationReportType);
        reportIllegalVerificationReport("IndividualReport element does not contain details.", //
            () -> {
                var vr = FACTORY_OASIS_VR.createVerificationReportType();
                vr.getIndividualReport().add(FACTORY_OASIS_VR.createIndividualReportType());
                return vr;
            });
        reportIllegalDetails("Details of IndividualReport element does not contain exactly one TimeStampValidityType.",
            FACTORY_DSS::createAnyType);
        reportIllegalDetails("Details of IndividualReport element does not contain exactly one TimeStampValidityType.", () -> {
            var details = FACTORY_DSS.createAnyType();
            details.getAny().add("cannotBeParsed");
            return details;
        });
        reportIllegalDetails("Details of IndividualReport element does not contain exactly one TimeStampValidityType.", () -> {
            var details = FACTORY_DSS.createAnyType();
            details.getAny().add(elementWithWrongType);
            return details;
        });
    }

    /**
     * Asserts that an incompatible declared CMS version is detected
     */
    @Test
    public void reportWrongCmsVersion() throws Exception
    {
        var tst = someTimeStampToken();
        var encoded = tst.getEncoded();
        assertThat("The 21st byte is the correct CMS version", encoded[21], is((byte)3));
        // Manipulate the CMS version in the ASN.1-structure
        encoded[21] = 2;
        var signedData = new CMSSignedData(encoded);
        var manipulatedToken = new TimeStampToken(signedData);
        var eCard = mock(ECard.class);
        when(eCard.verifyRequest(any())).thenReturn(verifyResponseOk(() -> null));
        var sut = sut(eCard);
        sut.setContext(new ErValidationContext(new Reference("dummy"), "", ""));
        var report = sut.validate(new Reference("dummy"), manipulatedToken);
        assertThat(report.getOverallResult().getResultMajor(), is("urn:oasis:names:tc:dss:1.0:detail:invalid"));
        assertThat(report.getOverallResult().getResultMinor(), is("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/invalidFormat"));
        var expectedMessage = "Invalid CMS version 2 in timestamp, the supported versions are 3 or 5";
        assertThat(report.getFormatted().getFormatOK().getResultMessage().getValue(), containsString(expectedMessage));
    }

    @Test
    public void noValidationWhenECardPortIsNull() throws Exception
    {
        var sut = sut((ECard)null);
        var timeStamp = someTimeStampToken();
        var ref = new Reference("dummy");

        var report = sut.validateInternal(ref, timeStamp);

        assertThat(report.getSummarizedMessage(), containsString("no online validation of time stamp done"));
    }

    /**
     * Asserts that the validator reports the given message for the given OptionalOutput which is responded by eCard.
     */
    private void reportIllegalOptionalOutput(String message, Supplier<AnyType> optionalOutput) throws Exception
    {
        var ref = new Reference("dummy");
        var tst = someTimeStampToken();
        var ecard = mock(ECard.class);
        var sut = sut(ecard);
        sut.setContext(new ErValidationContext(ref, "", ""));

        var response = verifyResponseOk(optionalOutput);

        when(ecard.verifyRequest(any())).thenReturn(response);
        var report = sut.validate(ref, tst);

        assertThat(report.getOverallResult().getResultMajor(), is("urn:oasis:names:tc:dss:1.0:detail:indetermined"));
        assertThat(report.getOverallResult().getResultMinor(),
            is("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError"));
        assertThat(report.getOverallResult().getResultMessage().getValue(), containsString("Illegal eCard response. " + message));

    }

    private VerifyResponse verifyResponseOk(Supplier<AnyType> optionalOutput)
    {
        var response = FACTORY_ECARD.createVerifyResponse();
        var result = FACTORY_DSS.createResult();
        result.setResultMajor("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok");
        response.setResult(result);
        response.setOptionalOutputs(optionalOutput.get());
        return response;
    }

    private TimeStampToken someTimeStampToken() throws IOException
    {
        var erBytes = TestUtils.decodeTestResource("/bin/example.ers.b64");
        var er = new ASN1EvidenceRecordParser().parse(erBytes);
        return er.getAtss().get(0).get(0).getTimeStampToken();
    }

    /**
     * Asserts that the validator reports the given message for the given VerificationReport which is responded by eCard.
     */
    private void reportIllegalVerificationReport(String message, Supplier<VerificationReportType> vr) throws Exception
    {
        var any = new AnyType();
        any.getAny().add(FACTORY_OASIS_VR.createVerificationReport(vr.get()));
        reportIllegalOptionalOutput(message, () -> any);
    }

    /**
     * Asserts that the validator reports the given message for the given IndividualReport details which are responded by eCard.
     */
    private void reportIllegalDetails(String message, Supplier<AnyType> details) throws Exception
    {
        var vr = FACTORY_OASIS_VR.createVerificationReportType();
        var ir = FACTORY_OASIS_VR.createIndividualReportType();
        ir.setDetails(details.get());
        vr.getIndividualReport().add(ir);
        reportIllegalVerificationReport(message, () -> vr);
    }

    protected ECardTimeStampValidator sut(String url) throws Exception
    {
        TestUtils.loadDefaultConfig();
        var profile = Configurator.getInstance().getProfile(Configurator.getInstance().getDefaultProfileName());
        profile.setValidationService(url);
        return new ECardTimeStampValidator();
    }

    protected ECardTimeStampValidator sut(ECard ecard)
    {
        ECard_Service eCardWebservice = when(mock(ECard_Service.class).getECard()).thenReturn(ecard).getMock();
        return new ECardTimeStampValidator(eCardWebservice);
    }

}
