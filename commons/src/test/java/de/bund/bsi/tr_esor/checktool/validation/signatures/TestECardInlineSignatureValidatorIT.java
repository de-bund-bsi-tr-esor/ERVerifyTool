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

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_XAIP;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.BeforeClass;
import org.junit.Test;

import com.sun.xml.ws.util.ByteArrayDataSource;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.data.InlineSignedDataObject;
import de.bund.bsi.tr_esor.checktool.parser.XaipParser;
import de.bund.bsi.tr_esor.checktool.validation.report.OasisDssResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.OasisDssResultMinor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.SignatureReportPart;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;

import jakarta.activation.DataHandler;
import jakarta.xml.bind.JAXBElement;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.DetailedSignatureReportType;


/**
 * Tests for {@link ECardInlineSignatureValidator} which require a running eCard service.
 */
@SuppressWarnings({"checkstyle:multiplestringliterals", "PMD.AvoidDuplicateLiterals"})
public class TestECardInlineSignatureValidatorIT
{

    private final ECardInlineSignatureValidator systemUnderTest;

    /**
     * Default constructor. The eCard URL used to create the service is derived from the default test configuration.
     */
    public TestECardInlineSignatureValidatorIT()
    {
        systemUnderTest = new ECardInlineSignatureValidator();
    }

    @BeforeClass
    public static void setUpClass() throws Exception
    {
        TestUtils.loadDefaultConfig();
    }

    static InlineSignatureValidationContext getValidContext() throws IOException
    {
        try (InputStream ins = TestUtils.class.getResourceAsStream("/xaip/signature/xaip_ok_pdfsig.xml"))
        {
            assertThat(ins).isNotNull();
            var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory("TR-ESOR"));
            var parser = new XaipParser(lXaipReader);
            parser.setInput(ins);
            var xaip = parser.parse().getXaip();
            var dataObject = xaip.getDataObjectsSection().getDataObject().get(0);
            var signedDataObject = new InlineSignedDataObject(new Reference(dataObject.getDataObjectID()), lXaipReader, dataObject);

            return new InlineSignatureValidationContext(signedDataObject, "TR-ESOR");
        }
    }

    /**
     * Asserts that in positive case a verification report is returned which states that the signature is math OK.
     */
    @Test
    public void providesReport() throws Exception
    {
        InlineSignatureValidationContext ctx = getValidContext();

        systemUnderTest.setContext(ctx);
        SignatureReportPart report = systemUnderTest.validate(ctx.getReference(), ctx.getObjectToValidate());

        DetailedSignatureReportType detailReport = extractDetailedSigReport(report);
        assertThat(detailReport.getFormatOK().getResultMajor()).endsWith("detail:valid");
        assertThat(detailReport.getSignatureOK().getSigMathOK().getResultMajor()).endsWith("detail:valid");
    }

    /**
     * Asserts that a dummy report is produced for unsigned binary data
     */
    @Test
    public void providesReportForUnsignedData()
    {
        var unsignedData = FACTORY_XAIP.createBinaryDataType();
        unsignedData.setMimeType("Application/Octet-Stream");
        unsignedData.setValue(new DataHandler(new ByteArrayDataSource("unsigned".getBytes(StandardCharsets.UTF_8),
            "application/octet-stream")));
        var unsignedDataObject = FACTORY_XAIP.createDataObjectType();
        unsignedDataObject.setBinaryData(unsignedData);
        unsignedDataObject.setDataObjectID("dummyID");
        var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory("TR-ESOR"));
        var inlineSignedData =
            new InlineSignedDataObject(new Reference(unsignedDataObject.getDataObjectID()), lXaipReader, unsignedDataObject);

        var context = new InlineSignatureValidationContext(inlineSignedData, "TR-ESOR");
        systemUnderTest.setContext(context);
        var report = systemUnderTest.validate(context.getReference(), context.getObjectToValidate());

        assertThat(report.getOverallResult().getResultMajor()).endsWith("detail:valid");
        var individualReport = report.getVr().getIndividualReport().get(0);
        assertThat(individualReport.getResult().getResultMajor()).endsWith(OasisDssResultMajor.REQUESTER_ERROR.getUri());
        assertThat(individualReport.getResult().getResultMinor()).endsWith(OasisDssResultMinor.ERROR_REQUEST_NOT_SUPPORTED.getUri());
        assertThat(individualReport.getResult().getResultMessage().getValue()).endsWith(
            "No inline signature found in data object. Detached signatures might be present.");
        assertThat(individualReport.getDetails()).isNull();
    }

    private DetailedSignatureReportType extractDetailedSigReport(SignatureReportPart report)
    {
        assertThat(report.getVr()).isNotNull();
        var entry = report.getVr().getIndividualReport().get(0).getDetails().getAny().get(0);
        assertThat(entry).isInstanceOf(JAXBElement.class);
        var detailReport = ((JAXBElement<?>)entry).getValue();
        assertThat(detailReport).isInstanceOf(DetailedSignatureReportType.class);
        return (DetailedSignatureReportType)detailReport;
    }

}
