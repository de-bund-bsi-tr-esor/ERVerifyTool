package de.bund.bsi.tr_esor.checktool.validation.signatures;

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_DSS;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.InternationalStringType;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss._1_0.core.schema.Result;


/**
 * Unit tests for the ECardResponseUtil
 *
 * @author ETR
 */
public class TestECardResponseUtil
{

    /**
     * This test case is based the answer provided by the verification interpreter web service if no signature is detected.
     */
    @Test
    public void detectsMissingSignatureFromOKandNoReport()
    {
        AnyType optionalOutputs = FACTORY_DSS.createAnyType();
        optionalOutputs.getAny().add(FACTORY_OASIS_VR.createVerificationReport(FACTORY_OASIS_VR.createVerificationReportType()));
        ResponseBaseType response = buildResponse(ECardResultMajor.OK, null, null, optionalOutputs);
        assertTrue("OK without report is an acceptable eCard result.", ECardResponseUtil.isAcceptableECardResult(response));
        assertTrue("OK without report is detected as no signature found.", ECardResponseUtil.isNoSignatureFound(response));
    }

    /**
     * This test case is based the answer provided by the crypto service library web service if there is no plugin that detected a signature
     * in the data provided.
     */
    @Test
    public void detectsMissingSignatureFromErrorNoPluginFound()
    {
        ResponseBaseType response =
            buildResponse(ECardResultMajor.ERROR, ECardResultMinor.INTERNAL_ERROR, ECardResultMessage.RESULTMESSAGE_NO_PLUGIN, null);
        assertFalse("No plugin found is detected as acceptable result.", ECardResponseUtil.isAcceptableECardResult(response));
        assertTrue("No plugin found is detected as no signature found.", ECardResponseUtil.isNoSignatureFound(response));
    }

    /**
     * This test case is represents the answer received from the crypto service library in case an unsigned XML or PDF was detected.
     */
    @Test
    public void detectsMissingSignatureFromSignatureFormatNotSupported()
    {
        ResponseBaseType response = buildResponse(ECardResultMajor.ERROR,
            ECardResultMinor.SIGNATURE_FORMAT_NOT_SUPPORTED,
            ECardResultMessage.RESULTMESSAGE_FORMAT_NOT_RECOGNIZED,
            null);
        assertFalse("SIGNATURE_FORMAT_NOT_SUPPORTED is detected as acceptable result.",
            ECardResponseUtil.isAcceptableECardResult(response));
        assertTrue("SIGNATURE_FORMAT_NOT_SUPPORTED found is detected as no signature found.",
            ECardResponseUtil.isNoSignatureFound(response));
    }

    /**
     * Assures that a warning which indicates no check could be executed is understood
     */
    @Test
    public void indeterminedOnECardWarning()
    {
        ResponseBaseType response = buildResponse(ECardResultMajor.WARNING, ECardResultMinor.PARAMETER_ERROR, null, null);
        assertTrue("ParameterError warning is accepted", ECardResponseUtil.isAcceptableECardResult(response));
        assertFalse("ParameterError is not detected as no signature found.", ECardResponseUtil.isNoSignatureFound(response));
    }

    /**
     * Assures that an error which indicates no check could be executed is understood
     */
    @Test
    public void erorsOnECardError()
    {
        ResponseBaseType response = buildResponse(ECardResultMajor.ERROR, ECardResultMinor.NO_PERMISSION, null, null);
        assertFalse("No permission is detected as technical error.", ECardResponseUtil.isAcceptableECardResult(response));
        assertFalse("No permission is not detected as no signature found.", ECardResponseUtil.isNoSignatureFound(response));
    }

    /**
     * Asserts a missing minor code for an ecard error is treated as an unacceptable eCard result
     */
    @Test
    public void errorsOnMissingECardMinor()
    {
        ResponseBaseType response = buildResponse(ECardResultMajor.ERROR, null, null, null);
        assertFalse("An error without message is detected as unacceptable result.", ECardResponseUtil.isAcceptableECardResult(response));
        assertFalse("An error without message is not detected as no signature found.", ECardResponseUtil.isNoSignatureFound(response));
    }

    /**
     * Asserts an unknown minor code for an ecard error is treated as an unacceptable eCard result
     */
    @Test
    public void errorsOnBadECardMinor()
    {
        ResponseBaseType response = buildResponse(ECardResultMajor.ERROR, "unknown_error", null, null);
        assertFalse("An unknown minor code is detected as unacceptable result.", ECardResponseUtil.isAcceptableECardResult(response));
        assertFalse("An unknown minor code is not detected no signature found.", ECardResponseUtil.isNoSignatureFound(response));
    }

    /**
     * Asserts an unknown minor code for an ecard error is treated as an unacceptable eCard result
     */
    @Test
    public void acceptsMissingContentWarning()
    {
        ResponseBaseType response =
            buildResponse(ECardResultMajor.WARNING, ECardResultMinor.DETACHED_SIGNATURE_WITHOUT_E_CONTENT, null, null);
        assertTrue("A result for missing eContent is detected as acceptable ecard result.",
            ECardResponseUtil.isAcceptableECardResult(response));
        assertFalse("A result for missing eContent is not detected no signature found.", ECardResponseUtil.isNoSignatureFound(response));
    }

    /**
     * Asserts an unknown minor code for an ecard error is treated as an unacceptable eCard result
     */
    @Test
    public void acceptsResultForInvalidSigature()
    {
        ResponseBaseType response = buildResponse(ECardResultMajor.ERROR, ECardResultMinor.WRONG_MESSAGE_DIGEST, null, null);
        assertTrue("A result for an invalid signature is detected as acceptable ecard result.",
            ECardResponseUtil.isAcceptableECardResult(response));
        assertFalse("A result for an invalid signature is not detected as no signature found.",
            ECardResponseUtil.isNoSignatureFound(response));
    }

    private ResponseBaseType buildResponse(String resultMajor, String resultMinor, String resultMessage, AnyType optionalOutputs)
    {
        Result result = FACTORY_DSS.createResult();
        result.setResultMajor(resultMajor);
        result.setResultMinor(resultMinor);
        InternationalStringType i18nMessage = FACTORY_DSS.createInternationalStringType();
        i18nMessage.setLang("EN");
        i18nMessage.setValue(resultMessage);
        result.setResultMessage(i18nMessage);

        ResponseBaseType response = FACTORY_DSS.createResponseBaseType();
        response.setResult(result);
        response.setOptionalOutputs(optionalOutputs);
        return response;
    }
}
