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


import static org.assertj.core.api.Assertions.assertThat;

import org.junit.BeforeClass;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.SignatureValidationTestHelper;
import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.validation.report.SignatureReportPart;

import jakarta.xml.bind.JAXBElement;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.DetailedSignatureReportType;


/**
 * Tests for {@link ECardDetachedSignatureValidator} which require a running eCard service.
 */
public class TestECardDetachedSignatureValidatorIT
{

    private final ECardDetachedSignatureValidator systemUnderTest;

    /**
     * Default constructor. The eCard URL used to create the service is derived from the eCard.url system property or as a default uses a
     * Verification Interpreter service provided on the the hostname crypto.
     */
    public TestECardDetachedSignatureValidatorIT()
    {
        systemUnderTest = new ECardDetachedSignatureValidator();
    }

    @BeforeClass
    public static void setUpClass() throws Exception
    {
        TestUtils.loadDefaultConfig();
    }

    /**
     * Asserts that in positive case a verification report is returned which states that the signature is math OK.
     */
    @Test
    public void providesReport() throws Exception
    {
        DetachedSignatureValidationContext ctx = SignatureValidationTestHelper.getValidContext();

        systemUnderTest.setContext(ctx);
        SignatureReportPart report = systemUnderTest.validate(ctx.getReference(), ctx.getObjectToValidate());

        DetailedSignatureReportType detailReport = extractDetailedSigReport(report);
        assertThat(detailReport.getFormatOK().getResultMajor()).endsWith("detail:valid");
        assertThat(detailReport.getSignatureOK().getSigMathOK().getResultMajor()).endsWith("detail:valid");
    }

    /**
     * Asserts that manipulated data is recognized as invalid.
     */
    @Test
    public void changedData() throws Exception
    {
        DetachedSignatureValidationContext ctx = SignatureValidationTestHelper.getValidContext();
        ctx.getProtectedDataByID().values().iterator().next()[5] = 0;

        systemUnderTest.setContext(ctx);
        SignatureReportPart report = systemUnderTest.validate(ctx.getReference(), ctx.getObjectToValidate());

        assertThat(extractDetailedSigReport(report).getSignatureOK().getSigMathOK().getResultMajor()).endsWith("detail:invalid");

    }

    /**
     * Asserts that a detached signature object that is not a signature is detected as not a signature
     */
    @Test
    public void noSignatureInCredential() throws Exception
    {
        DetachedSignatureValidationContext ctx = SignatureValidationTestHelper.getNoSignatureDetachedContext();

        systemUnderTest.setContext(ctx);
        SignatureReportPart report = systemUnderTest.validate(ctx.getReference(), ctx.getObjectToValidate());

        assertThat(report.getSummarizedMessage()).contains("No signature found in credential.");
    }

    private DetailedSignatureReportType extractDetailedSigReport(SignatureReportPart report)
    {
        assertThat(report.getVr()).isNotNull();
        Object entry = report.getVr().getIndividualReport().get(0).getDetails().getAny().get(0);
        assertThat(entry).isInstanceOf(JAXBElement.class);
        Object detailReport = ((JAXBElement<?>)entry).getValue();
        assertThat(detailReport).isInstanceOf(DetailedSignatureReportType.class);
        return (DetailedSignatureReportType)detailReport;
    }
}
