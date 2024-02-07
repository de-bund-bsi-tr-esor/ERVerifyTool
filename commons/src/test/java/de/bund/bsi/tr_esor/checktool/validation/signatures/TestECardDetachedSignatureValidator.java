/*-
 * Copyright (c) 2018
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

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_DSS;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.xml.namespace.QName;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.junit.Before;
import org.junit.Test;
import org.w3._2000._09.xmldsig_.SignatureType;
import org.w3._2000._09.xmldsig_.SignatureValueType;

import de.bund.bsi.ecard.api._1.VerifyRequest;
import de.bund.bsi.tr_esor.checktool.SignatureValidationTestHelper;
import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.SignatureReportPart;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss._1_0.core.schema.SignatureObject;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.DetailedSignatureReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.SignatureValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.SignedObjectIdentifierType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationResultType;


/**
 * Unit tests for {@link ECardDetachedSignatureValidator}.
 *
 * @author TT, WS, PRE, FAS
 */
public class TestECardDetachedSignatureValidator
{

    @Before
    public void loadTestConfig() throws Exception
    {
        TestUtils.loadDefaultConfig();
    }

    /**
     * Checks several get methods, assert that an unreachable eCard service produces an internal error with apprehensive message.
     */
    @Test
    public void notReachable() throws Exception
    {
        Configurator.getInstance().getProfile("custom").setValidationService("http://not-reachable:1234/eCardService");
        var sut = new ECardDetachedSignatureValidator();
        assertThat(sut.getRequiredContextClass()).isEqualTo(DetachedSignatureValidationContext.class);
        var ctx = SignatureValidationTestHelper.getValidContext();
        assertThat(ctx.getTargetClass()).isEqualTo(SignatureObject.class);
        sut.setContext(ctx);

        var report = sut.validate(ctx.getReference(), ctx.getObjectToValidate());
        assertThat(report.getOverallResult().getResultMinor()).isEqualTo(ECardResultMinor.INTERNAL_ERROR);
        assertThat(report.getOverallResult().getResultMessage().getValue()).startsWith("eCard webservice is unreachable");
        assertThat(report.getVr().getIndividualReport()).hasSize(1);
        assertThat(report.getVr().getIndividualReport().get(0).getResult().getResultMessage().getValue()).contains(
            "eCard webservice is unreachable");
    }

    /**
     * Checks that {@link SignatureReportPart} returns all the needed values. One test for report part does not justify whole new class.
     */
    @Test
    public void checkReportPart()
    {
        var sut = new SignatureReportPart(new Reference("dummy"));
        var vr = new VerificationReportType();
        sut.setVr(vr);
        assertThat(sut.findSignatureReportDetails()).isEmpty();

        var indivReport = new IndividualReportType();
        vr.getIndividualReport().add(indivReport);
        indivReport.setDetails(new AnyType());
        var elem =
            new JAXBElement<>(new QName("DetailedSignatureReport"), DetailedSignatureReportType.class, new DetailedSignatureReportType());
        indivReport.getDetails().getAny().add(elem);

        var dummySignature = "testSignature".getBytes(StandardCharsets.UTF_8);
        var signedObjectIdentifier = new SignedObjectIdentifierType();
        var signatureValue = new SignatureValueType();
        signatureValue.setValue(dummySignature);
        signedObjectIdentifier.setSignatureValue(signatureValue);
        indivReport.setSignedObjectIdentifier(signedObjectIdentifier);

        var signatureReportDetails = sut.findSignatureReportDetails();
        assertThat(signatureReportDetails).hasSize(1);
        assertThat(signatureReportDetails.get(dummySignature)).isInstanceOf(DetailedSignatureReportType.class);
    }

    /**
     * Asserts that a request can be created. Use this method in case requests should be checked manually.
     */
    @Test
    public void createRequest() throws Exception
    {
        Configurator.getInstance().getProfile("custom").setValidationService("http://some-url");
        var sut = new ECardDetachedSignatureValidator();
        var ctx = SignatureValidationTestHelper.getValidContext();
        sut.setContext(ctx);
        assertThat(sut.createVerifyRequest(ctx.getObjectToValidate())).isNotNull();
    }

    /**
     * Asserts result is indetermined if eCard does not produce report.
     */
    @Test
    public void eCardReportsError() throws IOException
    {
        Configurator.getInstance().getProfile("custom").setValidationService("http://some-url");
        var sut = new ECardDetachedSignatureValidator();
        var ctx = SignatureValidationTestHelper.getValidContext();

        sut.setContext(ctx);
        var report = sut.validate(ctx.getReference(), ctx.getObjectToValidate());
        assertThat(report.getOverallResult().getResultMajor()).isEqualTo(ValidationResultMajor.INDETERMINED.toString());
    }

    /**
     * Asserts that validation message points to missing optional output.
     */
    @Test
    public void generateValidationMessageOptionalOutputsMissing() throws IOException
    {
        var message = createSut().generateValidationMessage(null, null);

        assertThat(message).isEqualTo("Illegal eCard response. No optional outputs were received from the eCardService.");
    }

    /**
     * Asserts that validation message points to an empty optional output.
     */
    @Test
    public void generateValidationMessageOptionalOutputsEmpty() throws IOException
    {
        var response = new ResponseBaseType();
        response.setOptionalOutputs(new AnyType());

        var message = createSut().generateValidationMessage(response, null);

        assertThat(message).isEqualTo(
            "Illegal eCard response. The optional outputs section that was received from the eCardService is empty.");
    }

    /**
     * Asserts that validation message points to missing verification report in optional output.
     */
    @Test
    public void generateValidationMessageNoVR() throws IOException
    {
        var response = new ResponseBaseType();
        var optionalOutputs = new AnyType();
        var element = FACTORY_DSS.createDocument(FACTORY_DSS.createDocumentType());
        optionalOutputs.getAny().add(element);
        response.setOptionalOutputs(optionalOutputs);

        var message = createSut().generateValidationMessage(response, null);

        assertThat(message).isEqualTo("Illegal eCard response. OptionalOutput element is not a VerificationReportType.");
    }

    /**
     * Asserts that validation message points to not parseable response from eCard service.
     */
    @Test
    public void generateValidationMessageOptionalOutputNotParseable() throws IOException
    {
        var response = new ResponseBaseType();
        var optionalOutputs = new AnyType();
        var unexpectedObject = new Object();
        optionalOutputs.getAny().add(unexpectedObject);
        response.setOptionalOutputs(optionalOutputs);

        var message = createSut().generateValidationMessage(response, null);

        assertThat(message).isEqualTo("Illegal eCard response. Could not parse the existing optional outputs from the eCard response.");
    }

    /**
     * Asserts that no validation message is generated because of valid data.
     */
    @Test
    public void generateValidationMessageValid() throws IOException
    {
        var response = new ResponseBaseType();
        var optionalOutputs = new AnyType();
        var verificationReportType = FACTORY_OASIS_VR.createVerificationReportType();
        verificationReportType.getIndividualReport().add(new IndividualReportType());
        var element = FACTORY_OASIS_VR.createVerificationReport(verificationReportType);
        optionalOutputs.getAny().add(element);
        response.setOptionalOutputs(optionalOutputs);
        var result = new Result();
        result.setResultMajor(ValidationResultMajor.VALID.toString());
        response.setResult(result);

        var message = createSut().generateValidationMessage(response, null);

        assertThat(message).isNull();
    }

    /**
     * Asserts that validation message is generated because of an invalid result in SigMathOk and restricted validation mode.
     */
    @Test
    public void generateValidationMessageHashValueInvalidWithRestrictedValidation() throws IOException
    {
        var response = new ResponseBaseType();
        var optionalOutputs = new AnyType();
        var verificationReportType = FACTORY_OASIS_VR.createVerificationReportType();
        var individualReport = createIndividualReport(ValidationResultMajor.INVALID);
        verificationReportType.getIndividualReport().add(individualReport);
        var element = FACTORY_OASIS_VR.createVerificationReport(verificationReportType);
        optionalOutputs.getAny().add(element);
        response.setOptionalOutputs(optionalOutputs);
        var result = new Result();
        result.setResultMajor(ValidationResultMajor.VALID.toString());
        response.setResult(result);

        var signatureObject = new SignatureObject();
        signatureObject.setSignature(new SignatureType());

        var sut = new ECardDetachedSignatureValidator();
        var ctx = SignatureValidationTestHelper.getValidContext();
        ctx.withRestrictedValidation(true);
        sut.setContext(ctx);

        var message = sut.generateValidationMessage(response, signatureObject);

        assertThat(message).isEqualTo("Only Base64 encoded signatures can be validated via S4VerifyOnly");
    }

    /**
     * Asserts that no validation message is generated while in restricted validation mode.
     */
    @Test
    public void generateValidationMessageValidWithRestrictedValidation() throws IOException
    {
        var response = new ResponseBaseType();
        var optionalOutputs = new AnyType();
        var verificationReportType = FACTORY_OASIS_VR.createVerificationReportType();
        var individualReport = createIndividualReport(ValidationResultMajor.VALID);
        verificationReportType.getIndividualReport().add(individualReport);
        var element = FACTORY_OASIS_VR.createVerificationReport(verificationReportType);
        optionalOutputs.getAny().add(element);
        response.setOptionalOutputs(optionalOutputs);
        var result = new Result();
        result.setResultMajor(ValidationResultMajor.VALID.toString());
        response.setResult(result);

        var signatureObject = new SignatureObject();
        signatureObject.setSignature(new SignatureType());

        var sut = new ECardDetachedSignatureValidator();
        var ctx = SignatureValidationTestHelper.getValidContext();
        ctx.withRestrictedValidation(true);
        sut.setContext(ctx);

        var message = sut.generateValidationMessage(response, signatureObject);

        assertThat(message).isNull();
    }

    private static ECardDetachedSignatureValidator createSut() throws IOException
    {
        var sut = new ECardDetachedSignatureValidator();
        var ctx = SignatureValidationTestHelper.getValidContext();
        sut.setContext(ctx);
        return sut;
    }

    /**
     * For debugging: writes requests into a fixed file. That need arises because there are many ways to include data into a VerifyRequest
     * and it is likely that any service implementation supports not all of them.
     */
    public static void printRequest(VerifyRequest input)
    {
        try
        {
            var element = XmlHelper.toElement(input, VerifyRequest.class.getPackage().getName(), null);
            var tf = TransformerFactory.newInstance();
            var transformer = tf.newTransformer();
            var reportFile = new File("request.xml");
            transformer.transform(new DOMSource(element), new StreamResult(reportFile));
        }
        catch (JAXBException | TransformerException e)
        {
            throw new IllegalStateException(e);
        }
    }

    private static IndividualReportType createIndividualReport(ValidationResultMajor sigMathOkResult)
    {
        var individualReportDetail = new AnyType();
        var detailedSignatureReport = new DetailedSignatureReportType();
        var detailedSignatureReportJaxb = new JAXBElement<>(new QName("dummy"), DetailedSignatureReportType.class, detailedSignatureReport);
        var signatureValidityType = new SignatureValidityType();
        var sigMathOk = new VerificationResultType();
        sigMathOk.setResultMajor(sigMathOkResult.toString());
        signatureValidityType.setSigMathOK(sigMathOk);
        detailedSignatureReport.setSignatureOK(signatureValidityType);
        individualReportDetail.getAny().add(detailedSignatureReportJaxb);
        var individualReport = new IndividualReportType();
        individualReport.setDetails(individualReportDetail);
        return individualReport;
    }
}
