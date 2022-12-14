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
package de.bund.bsi.tr_esor.checktool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import javax.xml.transform.stream.StreamSource;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;

import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.vr.EvidenceRecordValidityType;


/**
 * Integration test for the main class only.
 */
public class TestMainIT extends TestBase
{

  private static String tmpDir;

  @Before
  public void setUpTmpDir()
  {
    var path = Paths.get(System.getProperty("java.io.tmpdir"), getClass().getSimpleName());
    tmpDir = path.toAbsolutePath().toString();
  }

  @Test
  public void testOnlineVerificationOfXaipWithMultipleErs() throws Exception
  {
    var individualReports = verify("xaip/xaip_ok_sig_ers_2version.xml",
                                   false,
                                   "command line parameter data/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V001",
                                   "command line parameter data/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V002",
                                   "HundesteuerAnmeldung_V001",
                                   "Hundename_V001",
                                   "fileSize_V001",
                                   "Hundename_V002",
                                   "Impfausweissignature_V001");

    SignatureValidationTestHelper.assertValidResult(individualReports.get("command line parameter data/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V001")
                                                                     .getResult());
    SignatureValidationTestHelper.assertValidResult(individualReports.get("command line parameter data/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V002")
                                                                     .getResult());
    SignatureValidationTestHelper.assertResult(individualReports.get("Impfausweissignature_V001").getResult(),
                                               ValidationResultMajor.VALID.toString(),
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
                                   false,
                                   "command line parameter data/evidenceRecord:ER_2.16.840.1.101.3.4.2.3_V001",
                                   "data_V001");

    SignatureValidationTestHelper.assertValidResult(individualReports.get("command line parameter data/evidenceRecord:ER_2.16.840.1.101.3.4.2.3_V001")
                                                                     .getResult());
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("data_V001"));
  }

  @Test
  public void checksNonQualifiedTimestampAsInvalid() throws Exception
  {
    var individualReports = verify("xaip/xaip_ok.xml",
                                   "xaip/xaip_ok.ers",
                                   "TR-ESOR",
                                   "command line parameter er",
                                   "Hundename_V001",
                                   "HundesteuerAnmeldung_V001",
                                   "fileSize_V001");
    var erReport = individualReports.get("command line parameter er");
    SignatureValidationTestHelper.assertResult(erReport.getResult(),
                                               "urn:oasis:names:tc:dss:1.0:detail:invalid",
                                               "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError",
                                               "atss/0/0/tsp: A checked timestamp should be qualified, but the quality of the timestamp was determined as: https://www.governikus.de/val-uri/timestamp-level-types/DTST");
  }

  @Test
  public void checksQualifiedTimestamp() throws Exception
  {
    var individualReports = verify("xaip/xaip_ok.xml",
                                   "xaip/xaip_ok_qualified.ers",
                                   "TR-ESOR",
                                   "command line parameter er",
                                   "Hundename_V001",
                                   "HundesteuerAnmeldung_V001",
                                   "fileSize_V001");
    var erReport = individualReports.get("command line parameter er");
    SignatureValidationTestHelper.assertValidResult(erReport.getResult());
    var evidenceRecordValidityType = ((JAXBElement<EvidenceRecordValidityType>)erReport.getDetails()
                                                                                       .getAny()
                                                                                       .get(0)).getValue();
    var chainingOk = evidenceRecordValidityType.getArchiveTimeStampSequence()
                                               .getArchiveTimeStampChain()
                                               .get(0)
                                               .getArchiveTimeStamp()
                                               .get(0)
                                               .getTimeStamp()
                                               .getCertificatePathValidity()
                                               .getPathValidityDetail()
                                               .getCertificateValidity()
                                               .get(0)
                                               .getChainingOK();
    assertThat(chainingOk.getResultMessage().getValue()).contains("QTST_EUMS_TL");
  }

  @Test
  public void signatureInXaip() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_sig.xml", true, "DO-02", "detachedSignature");

    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-02"));
    SignatureValidationTestHelper.assertValidResultsInIndividualReport(individualReports.get("detachedSignature"));

    assertFileExistsAndContains("xaip_ok_sig/detachedSignature/DO_01.bin", "compliance test data");
    assertFileExistsAndContains("xaip_ok_sig/DO_01/DO_01.bin", "compliance test data");
    assertFileExistsAndContains("xaip_ok_sig/DO_02/DO_02.bin", "content of data object DO-02");
    assertFileExistsAndContains("xaip_ok_sig/detachedSignature/signature.dat");
  }

  @Test
  public void signatureInMeta() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_meta_det_sig.xml",
                                   true,
                                   "DO_01",
                                   "detachedSignature");

    SignatureValidationTestHelper.assertValidResultsInIndividualReport(individualReports.get("detachedSignature"));

    assertFileExistsAndContains("singed_det_meta/detachedSignature/MD_01.xml", "compliance test data");
    assertFileExistsAndContains("singed_det_meta/DO_01/DO_01.bin", "content");
    assertFileExistsAndContains("singed_det_meta/detachedSignature/signature.dat");
  }

  @Test
  public void signatureInMetaEnveloped() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_meta_env_sig.xml", false, "DO_01", "MD_01");

    SignatureValidationTestHelper.assertValidResultsInIndividualReport(individualReports.get("MD_01"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO_01"));
  }

  @Test
  public void lxaipWithCredential() throws Exception
  {
    var individualReports = verify("lxaip/lxaip_ok_credentialdata.xml",
                                   null,
                                   "custom",
                                   "Impfausweissignature_V001",
                                   "HundesteuerAnmeldung_V001",
                                   "Hundename_V001",
                                   "fileSize_V001");

    SignatureValidationTestHelper.assertValidResultsInIndividualReport(individualReports.get("Impfausweissignature_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("HundesteuerAnmeldung_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("Hundename_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("fileSize_V001"));
  }

  @Test
  public void lxaipWithCredentialEr() throws Exception
  {
    var individualReports = verify("lxaip/lxaip_ok_er_cred.xml",
                                   null,
                                   "custom",
                                   "MDO_V001",
                                   "CT_V001",
                                   "command line parameter data/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V001");

    SignatureValidationTestHelper.assertValidResult(individualReports.get("command line parameter data/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V001")
                                                                     .getResult());
    SignatureValidationTestHelper.assertValidResultsInIndividualReport(individualReports.get("CT_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("MDO_V001"));
  }

  @Test
  public void lxaipWithDateDetachedEr() throws Exception
  {
    var individualReports = verify("lxaip/lxaip_ok.xml",
                                   "lxaip/lxaip_ok.ers.xml",
                                   "custom",
                                   "Hundename_V001",
                                   "HundesteuerAnmeldung_V001",
                                   "fileSize_V001",
                                   "/evidenceRecord/asn1EvidenceRecord");

    SignatureValidationTestHelper.assertValidResult(individualReports.get("/evidenceRecord/asn1EvidenceRecord")
                                                                     .getResult());
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("Hundename_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("HundesteuerAnmeldung_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("fileSize_V001"));
  }

  @Test
  public void lxaipWithMeta() throws Exception
  {
    var individualReports = verify("lxaip/lxaip_ok_metadata.xml",
                                   null,
                                   "custom",
                                   "HundesteuerAnmeldung_V001",
                                   "Hundename_V001");

    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("HundesteuerAnmeldung_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("Hundename_V001"));
  }

  @Test
  public void lxaipWithSingedMeta() throws Exception
  {
    var individualReports = verify("lxaip/lxaip_ok_meta_env_sig.xml", null, "custom", "MD_01", "DO_01");

    SignatureValidationTestHelper.assertValidResultsInIndividualReport(individualReports.get("MD_01"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO_01"));
  }

  @Test
  public void lxaipWithSingedData() throws Exception
  {
    var individualReports = verify("lxaip/lxaip_ok_env_sig.xml", null, "custom", "MD_01", "DO_01");

    SignatureValidationTestHelper.assertValidResultsInIndividualReport(individualReports.get("DO_01"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("MD_01"));
  }

  @Test
  public void lxaipWithMetaEr() throws Exception
  {
    var individualReports = verify("lxaip/lxaip_ok_er_metadata.xml",
                                   null,
                                   "custom",
                                   "HundesteuerAnmeldung_V001",
                                   "Hundename_V001",
                                   "fileSize_V001",
                                   "command line parameter data/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V001");

    SignatureValidationTestHelper.assertValidResult(individualReports.get("command line parameter data/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V001")
                                                                     .getResult());
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("HundesteuerAnmeldung_V001"));
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("Hundename_V001"));
  }

  @Test
  public void validateDoubleDetachedSignature() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xades_det_double.xml", true, "CR-01", "CR-01 (2)");

    SignatureValidationTestHelper.assertValidResultsInAllIndividualReports(individualReports);

    assertFileExistsAndContains("xaip_ok_xades_det_double/DO_01/DO_01.bin");
    assertFileExistsAndContains("xaip_ok_xades_det_double/CR_01/DO_01.bin");
    assertFileExistsAndContains("xaip_ok_xades_det_double/CR_01/signature.dat");
  }

  @Test
  public void testNotSignedDataObject() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_no_signature.xml", false, "DO-01");

    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-01"));
  }

  @Test
  public void testInvalidDetachedSignature() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_nok_sig.xml", true, "DO-02", "detachedSignature");
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-02"));
    var reportDetachedSignature = individualReports.get("detachedSignature");
    SignatureValidationTestHelper.assertResult(reportDetachedSignature.getResult(),
                                               ValidationResultMajor.INVALID.toString(),
                                               SignatureValidationTestHelper.INCORRECT_SIGNATURE);
    var detailedSignatureReport = SignatureValidationTestHelper.assertContainsDetailedSignatureReportType(reportDetachedSignature);
    SignatureValidationTestHelper.assertValidResult(detailedSignatureReport.getFormatOK());
    SignatureValidationTestHelper.assertInvalidSigMathResult(detailedSignatureReport.getSignatureOK()
                                                                                    .getSigMathOK());

    assertFileExistsAndContains("xaip_nok_sig/detachedSignature/DO_01.bin", "c0mpliance t3st data");
    assertFileExistsAndContains("xaip_nok_sig/DO_01/DO_01.bin", "c0mpliance t3st data");
    assertFileExistsAndContains("xaip_nok_sig/DO_02/DO_02.bin", "content of data object DO-02");
    assertFileExistsAndContains("xaip_nok_sig/detachedSignature/signature.dat");
  }

  /**
   * Reads an XAIP containing an XML signature as XML and validates it. Note that our present test data uses a
   * wrong canonicalization method "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" which breaks the
   * signature by embedding it into the XAIP. Thus, it must be checked as invalid.
   */
  @Test
  public void xmlSigWithWrongEmbedding() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_nok_xmlsig.xml", true, "detachedSignature");

    var reportDetachedSignature = individualReports.get("detachedSignature");
    SignatureValidationTestHelper.assertResult(reportDetachedSignature.getResult(),
                                               ValidationResultMajor.INVALID.toString(),
                                               SignatureValidationTestHelper.INCORRECT_SIGNATURE);
    var detailedSignatureReport = SignatureValidationTestHelper.assertContainsDetailedSignatureReportType(reportDetachedSignature);
    SignatureValidationTestHelper.assertValidResult(detailedSignatureReport.getFormatOK());
    SignatureValidationTestHelper.assertInvalidSigMathResult(detailedSignatureReport.getSignatureOK()
                                                                                    .getSigMathOK());

    assertFileExistsAndContains("xaip_nok_xmlsig/detachedSignature/data.bin", "Lorem ipsum dolor sit amet");
    assertFileExistsAndContains("xaip_nok_xmlsig/data/data.bin", "Lorem ipsum dolor sit amet");
  }

  /**
   * Reads an XAIP containing an XML signature as binary. Thus, there are no embedding problems and it should
   * be checked as valid.
   */
  @Test
  public void validateXmlSigBase64() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xmlsig_asBinary.xml", false, "detachedSignature");

    // TASK LZA-7045: Response enthält Fehler, obwohl Test von keinen Fehlern ausgeht
    // (im XSV gab wird derselbe Fehler angezeigt aber im Test nicht darauf geprüft)
    var individualReport = individualReports.get("detachedSignature");
    SignatureValidationTestHelper.assertResult(individualReport.getResult(),
                                               ValidationResultMajor.INVALID.toString(),
                                               SignatureValidationTestHelper.GENERAL_ERROR);
    var detailedSignatureReport = SignatureValidationTestHelper.assertContainsDetailedSignatureReportType(individualReport);
    SignatureValidationTestHelper.assertValidResult(detailedSignatureReport.getFormatOK());
    SignatureValidationTestHelper.assertValidResult(detailedSignatureReport.getSignatureOK().getSigMathOK());
    var pathValiditySummary = detailedSignatureReport.getCertificatePathValidity().getPathValiditySummary();
    assertThat(pathValiditySummary.getResultMajor()).isEqualTo("urn:oasis:names:tc:dss:1.0:detail:indetermined");
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
    var individualReports = verify("xaip/signature/xaip_ok_xmlsig_xmldata.xml", true, "CR-01");
    SignatureValidationTestHelper.assertValidResultsInAllIndividualReports(individualReports);

    assertFileExistsAndContains("xaip_ok_xmlsig_xmldata/DO_01/DO_01.xml",
                                "<ns1:Zusammenfassung>1234567890ßqwertzuiopü +#äölkjhgfdsa yxcvbnm,.-</ns1:Zusammenfassung>");
    assertFileExistsAndContains("xaip_ok_xmlsig_xmldata/CR_01/DO_01.xml",
                                "<ns1:Zusammenfassung>1234567890ßqwertzuiopü +#äölkjhgfdsa yxcvbnm,.-</ns1:Zusammenfassung>");
    assertFileExistsAndContains("xaip_ok_xmlsig_xmldata/CR_01/signature.dat");
  }

  /**
   * Assert that a XAIP containing a plain XAdES signature embedded as XML and binary signed data (which is
   * XML, but not canonicalized) can be validated successfully.
   */
  @Test
  public void validateXaipOkXadesDetXmlSingle() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xades_det_xml_single.xml", true, "CR-01");
    SignatureValidationTestHelper.assertValidResultsInAllIndividualReports(individualReports);

    assertFileExistsAndContains("xaip_ok_xades_det_xml_single/DO_01/DO_01.bin",
                                "<ns1:Zusammenfassung>1234567890ßqwertzuiopü +#äölkjhgfdsa yxcvbnm,.-</ns1:Zusammenfassung>");
    assertFileExistsAndContains("xaip_ok_xades_det_xml_single/CR_01/DO_01.bin",
                                "<ns1:Zusammenfassung>1234567890ßqwertzuiopü +#äölkjhgfdsa yxcvbnm,.-</ns1:Zusammenfassung>");
    assertFileExistsAndContains("xaip_ok_xades_det_xml_single/CR_01/signature.dat");
  }

  /**
   * Ensures XAdES enveloping are validated
   */
  @Test
  public void validatesEnvelopingXmlSig() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xmlsig_enveloping.xml", false, "CR-01");
    SignatureValidationTestHelper.assertValidResultsInAllIndividualReports(individualReports);
  }

  @Test
  public void validatesTwoCadesSigs() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_pdf_two_sigs.xml", false, "CR-01", "CR-01 (2)");

    SignatureValidationTestHelper.assertValidResultsInAllIndividualReports(individualReports);
  }

  /**
   * Asserts that checking a file with signed xmldata not containing exactly one child node fails.
   */
  @Test
  public void twoChildSignedXmlData()
  {
    assertThatThrownBy(() -> verify("xaip/signature/xaip_nok_xmlsig_xmldata_malformed_2childs.xml",
                                    false)).isInstanceOf(IllegalArgumentException.class)
                                           .hasMessage("The signed data object 'DO-01' has an xmlData element with more than one one child node");
  }

  /**
   * Validates a signature that was generated over non-canonicalized XML metadata. Expected result is a
   * mathematically invalid signature.
   */
  @Test
  public void validateInvalidCAdESMetadata() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_nok_xmlmeta_cades.xml", true, "DO-01", "CR-01");

    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-01"));
    var individualReport = individualReports.get("CR-01");
    var individualReportResult = individualReport.getResult();
    SignatureValidationTestHelper.assertResult(individualReportResult,
                                               ValidationResultMajor.INVALID.toString(),
                                               SignatureValidationTestHelper.INCORRECT_SIGNATURE);
    var detailedSignatureReport = SignatureValidationTestHelper.assertContainsDetailedSignatureReportType(individualReport);
    SignatureValidationTestHelper.assertValidResult(detailedSignatureReport.getFormatOK());
    SignatureValidationTestHelper.assertInvalidSigMathResult(detailedSignatureReport.getSignatureOK()
                                                                                    .getSigMathOK());

    assertFileExistsAndContains("xaip_nok_xmlmeta_cades/CR_01/MDO_01.xml", "uri:bsi.bund.de.tr03125.test.cr");
  }

  /**
   * Validates a signature that was generated over canonicalized XML metadata.
   */
  @Test
  public void validateValidCAdESMetadata() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xmlmeta_cades.xml", true, "DO-01", "CR-01");
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-01"));
    SignatureValidationTestHelper.assertValidResultsInIndividualReport(individualReports.get("CR-01"));

    assertFileExistsAndContains("xaip_ok_xmlmeta_cades/CR_01/MDO_01.xml", "uri:bsi.bund.de.tr03125.test.cr");
  }

  /**
   * Validates a XAdES signature that was generated over canonicalized XML metadata.
   */
  @Test
  public void validateValidXAdESMetadata() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_xmlmeta_xades.xml", true, "DO-01", "CR-01");
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-01"));
    SignatureValidationTestHelper.assertValidResultsInIndividualReport(individualReports.get("CR-01"));

    assertFileExistsAndContains("xaip_ok_xmlmeta_xades/CR_01/MDO_01.xml", "uri:bsi.bund.de.tr03125.test.cr");
  }

  /**
   * Validates a CAdES signature that was generated over simple text metadata content (no tags).
   */
  @Test
  public void validateValidTextMetadata() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_textmeta_cades.xml", true, "DO-01", "CR-01");
    SignatureValidationTestHelper.assertNoSignatureFound(individualReports.get("DO-01"));
    SignatureValidationTestHelper.assertValidResultsInIndividualReport(individualReports.get("CR-01"));

    assertFileExistsAndContains("xaip_ok_textmeta_cades/CR_01/MDO_01.xml", "metadata_content");
  }

  /**
   * Reads an XAIP containing an XML signature as binary. Thus, there are no embedding problems and it should
   * be checked as valid.
   */
  @Test
  public void validatePdfSig() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_pdfsig.xml", true, "DO-01", "DO-01 (2)");
    SignatureValidationTestHelper.assertValidResultsInAllIndividualReports(individualReports);

    assertFileExistsAndContains("xaip_ok_pdfsig/DO_01/DO_01.bin");
  }

  /**
   * Assert that a XAIP containing a timestamp credential protecting a data object can be validated as valid
   * successfully.
   */
  @Test
  public void validateValidTimeStamp() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_ok_tsp.xml", true, "CR-01");

    var individualReport = individualReports.get("CR-01");
    SignatureValidationTestHelper.assertResult(individualReport.getResult(),
                                               ValidationResultMajor.VALID.toString(),
                                               SignatureValidationTestHelper.ON_ALL_DOCUMENTS);
    var detailedSignatureReport = SignatureValidationTestHelper.assertContainsTimeStampValidityType(individualReport);
    SignatureValidationTestHelper.assertValidResult(detailedSignatureReport.getFormatOK());
    SignatureValidationTestHelper.assertValidResult(detailedSignatureReport.getSignatureOK().getSigMathOK());

    assertFileExistsAndContains("xaip_ok_tsp/CR_01/DO_01.bin");
  }

  /**
   * Assert that a XAIP containing a timestamp credential protecting a data object can be validated as invalid
   * successfully.
   */
  @Test
  public void validateInvalidTimeStamp() throws Exception
  {
    var individualReports = verify("xaip/signature/xaip_nok_tsp.xml", true, "CR-01");

    var individualReport = individualReports.get("CR-01");
    SignatureValidationTestHelper.assertResult(individualReport.getResult(),
                                               ValidationResultMajor.INVALID.toString(),
                                               SignatureValidationTestHelper.INCORRECT_SIGNATURE);
    var timeStampReport = SignatureValidationTestHelper.assertContainsTimeStampValidityType(individualReport);
    SignatureValidationTestHelper.assertValidResult(timeStampReport.getFormatOK());
    SignatureValidationTestHelper.assertInvalidSigMathResult(timeStampReport.getSignatureOK().getSigMathOK());

    assertFileExistsAndContains("xaip_nok_tsp/CR_01/DO_01.bin");
  }

  private static InputStream doVerify(String xaipName, String profile) throws IOException
  {
    var report = callMain("-conf", RES_DIR + "config.xml", "-data", RES_DIR + xaipName, "-profile", profile);
    return new ByteArrayInputStream(report.getBytes(StandardCharsets.UTF_8));
  }

  private static InputStream doVerifyWithDetachedEr(String xaipName, String er, String profile)
    throws IOException
  {
    var data = RES_DIR + xaipName;
    var erData = RES_DIR + er;
    var report = callMain("-conf", RES_DIR + "config.xml", "-data", data, "-er", erData, "-profile", profile);
    return new ByteArrayInputStream(report.getBytes(StandardCharsets.UTF_8));
  }

  private static Map<String, IndividualReportType> parseVerificationReport(VerificationReportType vrType,
                                                                           String... expectedKeys)
  {
    assertThat(vrType.getVerifierIdentity().getSAMLv2Identifier().getValue()).isEqualTo("urn:Beispiel");
    var result = new HashMap<String, IndividualReportType>();
    for ( var individualReport : vrType.getIndividualReport() )
    {
      var key = individualReport.getSignedObjectIdentifier().getFieldName();
      if (key == null)
      {
        key = individualReport.getSignedObjectIdentifier().getXPath();
      }
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

  private static VerificationReportType doVerify(String data, boolean dump) throws IOException, JAXBException
  {
    try (var reportStream = dump ? doVerifyAndDump(data) : doVerify(data, "custom"))
    {
      return reportStreamToReport(reportStream);
    }
  }

  private static VerificationReportType reportStreamToReport(InputStream reportStream) throws JAXBException
  {
    return XmlHelper.parse(new StreamSource(reportStream),
                           VerificationReportType.class,
                           XmlHelper.FACTORY_XAIP.getClass().getPackage().getName() + ":"
                                                         + XmlHelper.FACTORY_ASIC.getClass()
                                                                                 .getPackage()
                                                                                 .getName()
                                                         + ":"
                                                         + XmlHelper.FACTORY_ESOR_VR.getClass()
                                                                                    .getPackage()
                                                                                    .getName());
  }

  private static Map<String, IndividualReportType> verify(String xaipName,
                                                          String er,
                                                          String profile,
                                                          String... expectedKeys)
    throws IOException, JAXBException
  {
    try (var reportStream = er == null ? doVerify(xaipName, profile)
      : doVerifyWithDetachedEr(xaipName, er, profile))
    {
      var vrType = reportStreamToReport(reportStream);
      return parseVerificationReport(vrType, expectedKeys);
    }
  }

  private static Map<String, IndividualReportType> verify(String xaipName,
                                                          boolean dump,
                                                          String... expectedKeys)
    throws IOException, JAXBException
  {
    var vrType = doVerify(xaipName, dump);
    return parseVerificationReport(vrType, expectedKeys);
  }

  private static InputStream doVerifyAndDump(String xaipName) throws IOException
  {
    callMain("-conf",
             RES_DIR + "config.xml",
             "-data",
             RES_DIR + xaipName,
             "-profile",
             "custom",
             "-out",
             tmpDir);
    var path = Files.walk(Paths.get(tmpDir)).filter(f -> f.endsWith("report.xml")).findFirst().orElseThrow();
    return new FileInputStream(path.toString());
  }

  private void assertFileExistsAndContains(String filename, String... content) throws Exception
  {
    assertFileExists(filename);
    for ( var key : content )
    {
      assertFileContains(filename, key);
    }
  }
}
