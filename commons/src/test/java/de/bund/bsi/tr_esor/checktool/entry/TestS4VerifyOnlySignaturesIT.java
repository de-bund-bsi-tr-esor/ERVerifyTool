package de.bund.bsi.tr_esor.checktool.entry;

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ASIC;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ESOR_VR;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_XAIP;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;

import oasis.names.tc.dss._1_0.core.schema.DocumentType;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss._1_0.core.schema.VerifyRequest;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.SignedObjectIdentifierType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.bund.bsi.tr_esor.checktool.SignatureValidationTestHelper;
import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.OasisDssResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.OasisDssResultMinor;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.xaip.XAIPType;


public class TestS4VerifyOnlySignaturesIT
{

  private static final String S4_VERIFY_ONLY_BASE64_RESTRICTION = "Only Base64 encoded signatures can be validated via S4VerifyOnly";

  @BeforeClass
  public static void beforeClass() throws Exception
  {
    TestUtils.loadDefaultConfig();
  }

  @Test
  public void testOnlineVerificationOfXaipWithMultipleErs() throws Exception
  {
    var individualReports = verify("xaip/xaip_ok_sig_ers_2version.xml",
                                   "ER_2.16.840.1.101.3.4.2.1_V001",
                                   "ER_2.16.840.1.101.3.4.2.1_V002",
                                   "HundesteuerAnmeldung_V001",
                                   "Hundename_V001",
                                   "fileSize_V001",
                                   "Hundename_V002",
                                   "Impfausweis_V001",
                                   "Impfausweissignature_V001");

    SignatureValidationTestHelper.assertMajorSuccess(individualReports.get("ER_2.16.840.1.101.3.4.2.1_V001")
                                                                      .getResult());
    SignatureValidationTestHelper.assertMajorSuccess(individualReports.get("ER_2.16.840.1.101.3.4.2.1_V002")
                                                                      .getResult());
    SignatureValidationTestHelper.assertResult(individualReports.get("Impfausweissignature_V001").getResult(),
                                               OasisDssResultMajor.SUCCESS.toString(),
                                               SignatureValidationTestHelper.ON_ALL_DOCUMENTS);
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("HundesteuerAnmeldung_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("Hundename_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("fileSize_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("Hundename_V002"));
  }

  @Test
  public void testOnlineVerificationOfSingleDataObject() throws Exception
  {
    var individualReports = verify("xaip/xaip_ok_single_protected_data_object_resigned_and_rehased.xml",
                                   "ER_2.16.840.1.101.3.4.2.3_V001",
                                   "data_V001");

    SignatureValidationTestHelper.assertMajorSuccess(individualReports.get("ER_2.16.840.1.101.3.4.2.3_V001")
                                                                      .getResult());
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("data_V001"));
  }

  /**
   * FIXME exchange test data for valid result
   */
  @Test
  public void signatureInXaip() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_sig.xml", "DO-01", "DO-02", "detachedSignature");

    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-02"));
    SignatureValidationTestHelper.assertInsufficientInformationInIndividualReport(individualReports.get("detachedSignature"),
                                                                                  OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR.getUri());
  }

  /**
   * FIXME exchange test data for valid result
   */
  @Test
  public void validateDoubleDetachedSignature() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xades_det_double.xml",
                                   "DO-01",
                                   "CR-01",
                                   "CR-01 (2)");

    SignatureValidationTestHelper.assertInsufficientInformationInIndividualReport(individualReports.get("CR-01"),
                                                                                  OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR.getUri());
    SignatureValidationTestHelper.assertInsufficientInformationInIndividualReport(individualReports.get("CR-01 (2)"),
                                                                                  OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR.getUri());
  }

  @Test
  public void testNotSignedDataObject() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_no_signature.xml", "DO-01");

    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-01"));
  }

  @Test
  public void testInvalidDetachedSignature() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_nok_sig.xml", "DO-01", "DO-02", "detachedSignature");

    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-02"));
    var reportDetachedSignature = individualReports.get("detachedSignature");
    SignatureValidationTestHelper.assertResult(reportDetachedSignature.getResult(),
                                               OasisDssResultMajor.REQUESTER_ERROR.toString(),
                                               SignatureValidationTestHelper.INCORRECT_SIGNATURE);
    var detailedSignatureReport = SignatureValidationTestHelper.assertContainsDetailedSignatureReportType(reportDetachedSignature);
    SignatureValidationTestHelper.assertMajorSuccess(detailedSignatureReport.getFormatOK());
    SignatureValidationTestHelper.assertInvalidSigMathResult(detailedSignatureReport.getSignatureOK()
                                                                                    .getSigMathOK());
  }

  /**
   * Reads an XAIP containing an XML signature as XML and validates it. Note that our present test data uses a
   * wrong canonicalization method "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" which breaks the
   * signature by embedding it into the XAIP. Thus, it must be checked as invalid.
   */
  @Test
  public void xmlSigWithWrongEmbedding() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_nok_xmlsig.xml", "data", "detachedSignature");

    var reportDetachedSignature = individualReports.get("detachedSignature");
    SignatureValidationTestHelper.assertResult(reportDetachedSignature.getResult(),
                                               OasisDssResultMajor.INSUFFICIENT_INFORMATION.toString(),
                                               SignatureValidationTestHelper.PARAMETER_ERROR,
                                               S4_VERIFY_ONLY_BASE64_RESTRICTION);
  }

  /**
   * Reads an XAIP containing an XML signature as binary. Thus, there are no embedding problems and it should
   * be checked as valid.
   */
  @Test
  public void validateXmlSigBase64() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xmlsig_asBinary.xml", "data", "detachedSignature");

    // TASK LZA-7045: Response enthält Fehler, obwohl Test von keinen Fehlern ausgeht
    // (im XSV gab wird derselbe Fehler angezeigt aber im Test nicht darauf geprüft)
    var individualReport = individualReports.get("detachedSignature");
    SignatureValidationTestHelper.assertResult(individualReport.getResult(),
                                               OasisDssResultMajor.RESPONDER_ERROR.toString(),
                                               SignatureValidationTestHelper.GENERAL_ERROR);
    var detailedSignatureReport = SignatureValidationTestHelper.assertContainsDetailedSignatureReportType(individualReport);
    SignatureValidationTestHelper.assertMajorSuccess(detailedSignatureReport.getFormatOK());
    SignatureValidationTestHelper.assertMajorSuccess(detailedSignatureReport.getSignatureOK().getSigMathOK());
    var pathValiditySummary = detailedSignatureReport.getCertificatePathValidity().getPathValiditySummary();
    assertThat(pathValiditySummary.getResultMajor()).isEqualTo(ValidationResultMajor.INDETERMINED.toString());
    assertThat(pathValiditySummary.getResultMinor()).isEqualTo("GENERIC");
    assertThat(pathValiditySummary.getResultMessage()
                                  .getValue()).isEqualTo("x509_key_usage,\nrevocation_status_not_available_self_signed_ee");
  }

  /**
   * Assert that a XAIP containing a plain XAdES signature embedded as XML and XML data can be validated
   * successfully. The xmlData must contain exactly one child node. When generating test data, pay attention
   * that the data object will be canonicalized using the XAIP canonicalization algorithm which must match the
   * signatures canonicalization algorithm.
   */
  @Test
  public void validateXmlSig() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xmlsig_xmldata.xml", "CR-01");

    SignatureValidationTestHelper.assertResult(individualReports.get("CR-01").getResult(),
                                               OasisDssResultMajor.INSUFFICIENT_INFORMATION.toString(),
                                               SignatureValidationTestHelper.PARAMETER_ERROR,
                                               S4_VERIFY_ONLY_BASE64_RESTRICTION);
  }

  /**
   * Assert that a XAIP containing a plain XAdES signature embedded as XML and binary signed data (which is
   * XML, but not canonicalized) can be validated successfully.
   */
  @Test
  public void validateXaipOkXadesDetXmlSingle() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xades_det_xml_single.xml", "DO-01", "CR-01");

    SignatureValidationTestHelper.assertResult(individualReports.get("CR-01").getResult(),
                                               OasisDssResultMajor.INSUFFICIENT_INFORMATION.toString(),
                                               SignatureValidationTestHelper.PARAMETER_ERROR,
                                               S4_VERIFY_ONLY_BASE64_RESTRICTION);
  }

  /**
   * Ensures XAdES enveloping are validated
   */
  @Test
  public void validatesEnvelopingXmlSig() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xmlsig_enveloping.xml", "CR-01");

    SignatureValidationTestHelper.assertResult(individualReports.get("CR-01").getResult(),
                                               OasisDssResultMajor.INSUFFICIENT_INFORMATION.toString(),
                                               SignatureValidationTestHelper.PARAMETER_ERROR,
                                               S4_VERIFY_ONLY_BASE64_RESTRICTION);
  }

  /**
   * FIXME exchange test data for valid result
   */
  @Test
  public void validatesTwoCadesSigs() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_pdf_two_sigs.xml", "DO-01", "CR-01", "CR-01 (2)");

    SignatureValidationTestHelper.assertInsufficientInformationInIndividualReport(individualReports.get("CR-01"),
                                                                                  OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR.getUri());
    SignatureValidationTestHelper.assertInsufficientInformationInIndividualReport(individualReports.get("CR-01 (2)"),
                                                                                  OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR.getUri());
  }

  /**
   * Asserts that checking a file with signed xmldata not containing exactly one child node fails.
   */
  @Test
  public void twoChildSignedXmlData()
  {
    assertThatThrownBy(() -> verify("xaip/signature/xaip_nok_xmlsig_xmldata_malformed_2childs.xml")).isInstanceOf(IllegalArgumentException.class)
                                                                                                    .hasMessage("The signed data object 'DO-01' has an xmlData element with more than one one child node");
  }

  /**
   * Validates a signature that was generated over non-canonicalized XML metadata. Expected result is a
   * mathematically invalid signature.
   */
  @Test
  public void validateInvalidCAdESMetadata() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_nok_xmlmeta_cades.xml", "DO-01", "CR-01");

    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-01"));
    var individualReport = individualReports.get("CR-01");
    var individualReportResult = individualReport.getResult();
    SignatureValidationTestHelper.assertResult(individualReportResult,
                                               OasisDssResultMajor.REQUESTER_ERROR.toString(),
                                               SignatureValidationTestHelper.INCORRECT_SIGNATURE);
    var detailedSignatureReport = SignatureValidationTestHelper.assertContainsDetailedSignatureReportType(individualReport);
    SignatureValidationTestHelper.assertMajorSuccess(detailedSignatureReport.getFormatOK());
    SignatureValidationTestHelper.assertInvalidSigMathResult(detailedSignatureReport.getSignatureOK()
                                                                                    .getSigMathOK());
  }

  /**
   * Validates a signature that was generated over canonicalized XML metadata. Note: Contrary to validation
   * via CLI the result here is invalid because of removed line feeds on submit via S4 port
   */
  @Test
  public void validateCAdESMetadataInvalidViaS4() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xmlmeta_cades.xml", "DO-01", "CR-01");

    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-01"));
    // result is valid via CLI, but invalid via S4
    SignatureValidationTestHelper.assertResult(individualReports.get("CR-01").getResult(),
                                               OasisDssResultMajor.REQUESTER_ERROR.toString(),
                                               SignatureValidationTestHelper.INCORRECT_SIGNATURE);
  }

  /**
   * Validates a XAdES signature that was generated over canonicalized XML metadata.
   */
  @Test
  public void validateValidXAdESMetadata() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xmlmeta_xades.xml", "DO-01", "CR-01");

    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-01"));
    SignatureValidationTestHelper.assertResult(individualReports.get("CR-01").getResult(),
                                               OasisDssResultMajor.INSUFFICIENT_INFORMATION.toString(),
                                               SignatureValidationTestHelper.PARAMETER_ERROR,
                                               S4_VERIFY_ONLY_BASE64_RESTRICTION);
  }

  /**
   * Validates a CAdES signature that was generated over simple text metadata content (no tags). FIXME
   * exchange test data for valid result
   */
  @Test
  public void validateValidTextMetadata() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_textmeta_cades.xml", "MDO-01", "DO-01", "CR-01");

    SignatureValidationTestHelper.assertInsufficientInformationInIndividualReport(individualReports.get("CR-01"),
                                                                                  OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR.getUri());
  }

  /**
   * Reads an XAIP containing an XML signature as binary. Thus, there are no embedding problems and it should
   * be checked as valid. FIXME exchange test data for valid result
   */
  @Test
  public void validatePdfSig() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_pdfsig.xml", "DO-01", "DO-01 (2)");

    SignatureValidationTestHelper.assertInsufficientInformationInIndividualReport(individualReports.get("DO-01"),
                                                                                  OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR.getUri());
    SignatureValidationTestHelper.assertInsufficientInformationInIndividualReport(individualReports.get("DO-01 (2)"),
                                                                                  OasisDssResultMinor.ERROR_RESPONSE_GENERAL_ERROR.getUri());
  }

  /**
   * Assert that a XAIP containing a timestamp credential protecting a data object can be validated as valid
   * successfully.
   */
  @Test
  public void validateValidTimeStamp() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_tsp.xml", "DO-01", "CR-01");

    var individualReport = individualReports.get("CR-01");
    SignatureValidationTestHelper.assertResult(individualReport.getResult(),
                                               OasisDssResultMajor.SUCCESS.toString(),
                                               SignatureValidationTestHelper.ON_ALL_DOCUMENTS);
    var detailedSignatureReport = SignatureValidationTestHelper.assertContainsTimeStampValidityType(individualReport);
    SignatureValidationTestHelper.assertMajorSuccess(detailedSignatureReport.getFormatOK());
    SignatureValidationTestHelper.assertMajorSuccess(detailedSignatureReport.getSignatureOK().getSigMathOK());
  }

  /**
   * Assert that a XAIP containing a timestamp credential protecting a data object can be validated as invalid
   * successfully.
   */
  @Test
  public void validateInvalidTimeStamp() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_nok_tsp.xml", "DO-01", "CR-01");

    var individualReport = individualReports.get("CR-01");
    SignatureValidationTestHelper.assertResult(individualReport.getResult(),
                                               OasisDssResultMajor.REQUESTER_ERROR.toString(),
                                               SignatureValidationTestHelper.INCORRECT_SIGNATURE);
    var timeStampReport = SignatureValidationTestHelper.assertContainsTimeStampValidityType(individualReport);
    SignatureValidationTestHelper.assertMajorSuccess(timeStampReport.getFormatOK());
    SignatureValidationTestHelper.assertInvalidSigMathResult(timeStampReport.getSignatureOK().getSigMathOK());
  }

  /**
   * Validates a LXAIP with a simple text metadata content.
   */
  @Test
  public void validateValidLXaipMeta() throws Exception
  {
    var individualReports = verify("lxaip/lxaip_ok_er_metadata.xml",
                                   "Hundename_V001",
                                   "fileSize_V001",
                                   "HundesteuerAnmeldung_V001",
                                   "ER_2.16.840.1.101.3.4.2.1_V001");

    SignatureValidationTestHelper.assertMajorSuccess(individualReports.get("ER_2.16.840.1.101.3.4.2.1_V001")
                                                                      .getResult());
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("Hundename_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("HundesteuerAnmeldung_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("fileSize_V001"));
  }

  /**
   * Validates a LXAIP with a detached signature.
   */
  @Test
  public void validateValidLXaipCredential() throws Exception
  {
    var individualReports = verify("lxaip/lxaip_ok_er_cred.xml",
                                   "CT_V001",
                                   "MDO_V001",
                                   "D0_V001",
                                   "ER_2.16.840.1.101.3.4.2.1_V001");

    SignatureValidationTestHelper.assertMajorSuccess(individualReports.get("ER_2.16.840.1.101.3.4.2.1_V001")
                                                                      .getResult());
    SignatureValidationTestHelper.assertMajorSuccessInIndividualReport(individualReports.get("CT_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("MDO_V001"));
  }

  private Map<String, IndividualReportType> verify(String fileName, String... expectedKeys) throws Exception
  {
    VerifyRequest request = createVerifyRequest(fileName);
    var response = new S4VerifyOnly().verify(request);
    assertThat(response.getRequestID()).isEqualTo(request.getRequestID());
    var verificationReport = handleVerificationReport(response);

    assertThat(verificationReport.getVerifierIdentity()
                                 .getSAMLv2Identifier()
                                 .getValue()).isEqualTo("urn:Beispiel");
    var result = new HashMap<String, IndividualReportType>();
    for ( var individualReport : verificationReport.getIndividualReport() )
    {
      var key = generateKey(individualReport.getSignedObjectIdentifier());
      int i = 2;
      while (result.containsKey(key))
      {
        key = String.format("%s (%d)", key, i++);
      }
      result.put(key, individualReport);
    }
    assertThat(result).containsOnlyKeys(expectedKeys);
    return result;
  }

  private String generateKey(SignedObjectIdentifierType signedObjectIdentifier)
  {
    var xPath = signedObjectIdentifier.getXPath();
    if (xPath == null)
    {
      return signedObjectIdentifier.getFieldName();
    }

    var matcher = Pattern.compile(".*@.*='(ER.*)'.*").matcher(xPath);
    assertThat(matcher.find()).isTrue();
    return matcher.group(1);
  }

  private VerifyRequest createVerifyRequest(String fileName) throws JAXBException, IOException
  {
    var request = XmlHelper.FACTORY_DSS.createVerifyRequest();
    request.setRequestID(UUID.randomUUID().toString());
    request.setOptionalInputs(XmlHelper.FACTORY_DSS.createAnyType());
    request.setProfile("custom");

    var returnvr = FACTORY_OASIS_VR.createReturnVerificationReport();
    returnvr.setReportDetailLevel(ReportDetailLevel.ALL_DETAILS.toString());
    var optIn = XmlHelper.toElement(returnvr, FACTORY_OASIS_VR.getClass().getPackage().getName(), null);
    request.getOptionalInputs().getAny().add(optIn);

    var document = newDocument(request);
    var inlineXMLType = XmlHelper.FACTORY_DSS.createInlineXMLType();
    document.setInlineXML(inlineXMLType);
    try (var ins = TestS4VerifyOnly.class.getResourceAsStream("/" + fileName))
    {
      inlineXMLType.setAny(toElement(XmlHelper.parseXaip(ins)));
    }
    return request;
  }

  /**
   * Returns the verification report in a response, asserts that it exists and satisfies XML schema.
   */
  private VerificationReportType handleVerificationReport(ResponseBaseType resp) throws Exception
  {
    var vrElement = (Element)resp.getOptionalOutputs().getAny().get(0);
    var path = FACTORY_OASIS_VR.getClass().getPackage().getName() + ":"
               + FACTORY_ESOR_VR.getClass().getPackage().getName();
    var report = XmlHelper.parse(new DOMSource(vrElement), VerificationReportType.class, path);
    assertThat(report).isNotNull();
    return report;
  }

  private DocumentType newDocument(VerifyRequest request)
  {
    if (request.getInputDocuments() == null)
    {
      request.setInputDocuments(XmlHelper.FACTORY_DSS.createInputDocuments());
    }
    var document = XmlHelper.FACTORY_DSS.createDocumentType();
    request.getInputDocuments().getDocumentOrTransformedDataOrDocumentHash().add(document);
    return document;
  }

  /**
   * Simulates that content of any-elements arrives in the deployed web service as element.
   */
  private Element toElement(XAIPType xaip) throws JAXBException
  {
    var ctx = JAXBContext.newInstance(FACTORY_XAIP.getClass().getPackage().getName() + ":"
                                      + FACTORY_ASIC.getClass().getPackage().getName());
    var result = new DOMResult();
    ctx.createMarshaller().marshal(FACTORY_XAIP.createXAIP(xaip), result);
    return ((Document)result.getNode()).getDocumentElement();
  }
}
