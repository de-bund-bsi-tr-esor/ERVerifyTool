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
package de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Arrays;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.tsp.TSTInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentMatchers;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Test for Basis-ERS-Profil validator for content info element from a RFC3161 time stamp.
 *
 * @author BVO, HMA, MO
 */
@SuppressWarnings("PMD.NullAssignment")
public class TestContentInfoChecker
{

  private static final Reference REF = new Reference("test");

  /**
   * Set up default configuration.
   *
   * @throws Exception
   */
  @BeforeClass
  public static void setUpClass() throws Exception
  {
    TestUtils.loadDefaultConfig();
  }

  /**
   * Tests the validator with a mocked ContentInfo element that conforms to Basis-ERS-Profil. Assert that the
   * result is valid.
   *
   * @throws Exception
   */
  @Test
  public void testCheckSignedDataValid() throws Exception
  {
    var formatOk = new FormatOkReport(REF);
    var systemUnderTest = new ContentInfoChecker(formatOk);
    systemUnderTest.checkContentInfo(REF, mockContentInfo(true, false));
    assertThat(formatOk.getOverallResult().getResultMajor(), endsWith(":valid"));
  }

  /**
   * Tests the validator with mocked ContentInfo element that violates the Basis-ERS-Profil in the most
   * possible way. Assert all expected error messages are present and the result is invalid.
   *
   * @throws Exception
   */
  @Test
  public void testCheckSignedDataInvalid() throws Exception
  {
    var formatOk = new FormatOkReport(REF);
    var systemUnderTest = new ContentInfoChecker(formatOk);
    systemUnderTest.checkContentInfo(REF, mockContentInfo(false, false));
    assertThat(formatOk.getOverallResult().getResultMajor(), endsWith(":invalid"));
    var msgs = new String[]{"contentType OID of time stamp is not " + ContentInfoChecker.OID_PKCS7_SIGNEDDATA,
                            "Invalid CMS version 4 in timestamp, the supported version is 3",
                            "digestAlgorithms must be filled", "encapContentInfo must be filled",
                            "certificates must be filled",
                            "certs from BasicOCSPResponse must contain at least one element",
                            "ResponderID from BasicOCSPResponse must use byName choice", "version must be 1",
                            "sid must be of type IssuerAndSerialNumber",
                            "algorithm must be equal to one of SignedData.digestAlgorithms",
                            "signatureAlgorithm must be present", "signatureValue must be present",
                            "unsignedAttrs must be omitted", "attributes must be DER encoded",
                            "attribute must contain a type and a value set",
                            "content-type must be " + ContentInfoChecker.OID_TST_INFO,
                            "attribute must have a value set",
                            "SigningCertificateV2 must contain at least one ESSCertIDv2"};
    Arrays.stream(msgs).forEach(s -> assertThat(formatOk.getSummarizedMessage(), containsString(s)));
  }

  /**
   * Tests the validator with mocked ContentInfo element with alternative violations of the Basis-ERS-Profil.
   * Assert all expected error messages are present and the result is invalid.
   *
   * @throws Exception
   */
  @Test
  public void testCheckSignedDataWrongFormat() throws Exception
  {
    var formatOk = new FormatOkReport(REF);
    var systemUnderTest = new ContentInfoChecker(formatOk);
    systemUnderTest.checkContentInfo(REF, mockContentInfo(true, true));
    assertThat(formatOk.getOverallResult().getResultMajor(), endsWith(":invalid"));
    var msgs = new String[]{"certificates must only contain elements of type Certificate",
                            "content must be present and of type TSTInfo",
                            "content-type must be " + ContentInfoChecker.OID_TST_INFO,
                            "OtherRevocationInfoFormat must contain a BasicOCSPResponse",
                            "signerInfos must contain exactly one element"};
    Arrays.stream(msgs).forEach(s -> assertThat(formatOk.getSummarizedMessage(), containsString(s)));
  }

  /**
   * Tests a violation of Basis-ERS-Profil in content info, assert an invalid result and the appropriate error
   * message.
   *
   * @throws Exception
   */
  @Test
  public void testCheckContentInfo() throws Exception
  {
    ContentInfo ci = when(mock(ContentInfo.class).getContent()).thenReturn(new ASN1Integer(123)).getMock();
    when(ci.getContentType()).thenReturn(new ASN1ObjectIdentifier(ContentInfoChecker.OID_PKCS7_SIGNEDDATA));
    var formatOk = new FormatOkReport(REF);
    var systemUnderTest = new ContentInfoChecker(formatOk);
    systemUnderTest.checkContentInfo(REF, ci);
    assertThat(formatOk.getSummarizedMessage(),
               containsString("Could not parse element, error was: unknown object"));
  }

  /**
   * Tests a violation of Basis-ERS-Profil in signed data, assert an invalid result and the appropriate error
   * message.
   *
   * @throws Exception
   */
  @Test
  public void testCheckSignedData() throws Exception
  {
    SignedData signedData = when(mock(SignedData.class).getCRLs()).thenReturn(new BERSet()).getMock();
    when(signedData.getVersion()).thenReturn(new ASN1Integer(3));
    var formatOk = new FormatOkReport(REF);
    var systemUnderTest = new ContentInfoChecker(formatOk);
    systemUnderTest.checkSignedData(REF, signedData);
    assertThat(formatOk.getSummarizedMessage(), containsString("CRLs must be filled"));
  }

  /**
   * Tests a violation of Basis-ERS-Profil in RevocationInfoChoices, assert an invalid result and the
   * appropriate error message.
   *
   * @throws Exception
   */
  @Test
  public void testCheckRevocationInfoChoices() throws Exception
  {
    ASN1Set revocationInfoChoices = new BERSet(new DERUTF8String("dummy"));
    var formatOk = new FormatOkReport(REF);
    var systemUnderTest = new ContentInfoChecker(formatOk);
    systemUnderTest.checkRevocationInfoChoices(REF, revocationInfoChoices);
    assertThat(formatOk.getSummarizedMessage(),
               containsString("RevocationInfoChoice must be either CertificateList or OtherRevocationInfoFormat"));
  }

  /**
   * Tests a violation of Basis-ERS-Profil in ContentType, assert an invalid result and the appropriate error
   * message.
   *
   * @throws Exception
   */
  @Test
  public void testCheckContentTypeAttribute() throws Exception
  {
    var emptyAttribute = new Attribute(new ASN1ObjectIdentifier("1.2.3"), new BERSet());
    var formatOk = new FormatOkReport(REF);
    var systemUnderTest = new ContentInfoChecker(formatOk);
    systemUnderTest.checkContentTypeAttribute(REF, emptyAttribute);
    assertThat(formatOk.getSummarizedMessage(), containsString("attribute must have a value set"));
  }

  /**
   * Tests some violations of Basis-ERS-Profil in SigningCertificateV2, assert an invalid result and the
   * appropriate error message.
   *
   * @throws Exception
   */
  @Test
  public void testCheckSigningCertificateAttribute() throws Exception
  {
    var formatOk = new FormatOkReport(REF);
    var systemUnderTest = new ContentInfoChecker(formatOk);
    var emptyAttribute = new Attribute(new ASN1ObjectIdentifier("1.2.3"), new BERSet());
    systemUnderTest.checkSigningCertificateAttribute(REF, emptyAttribute);
    assertThat(formatOk.getSummarizedMessage(), containsString("attribute must have a value set"));

    var notScV2Attribute = new Attribute(new ASN1ObjectIdentifier("1.2.3"),
                                         new BERSet(new DERUTF8String("dummy")));
    systemUnderTest.checkSigningCertificateAttribute(REF, notScV2Attribute);
    assertThat(formatOk.getSummarizedMessage(), containsString("attribute must be SigningCertificateV2"));

    var certs = new BERSequence(new DERUTF8String("not a sequence"));
    var scv2seq = new BERSequence(certs);
    var scv2 = SigningCertificateV2.getInstance(scv2seq);
    var invalidScV2Attribute = new Attribute(new ASN1ObjectIdentifier("1.2.3"), new BERSet(scv2));
    systemUnderTest.checkSigningCertificateAttribute(REF, invalidScV2Attribute);
    assertThat(formatOk.getSummarizedMessage(),
               containsString("ESSCertIDv2 reference is not conform to RFC5035"));
  }

  private ContentInfo mockContentInfo(boolean valid, boolean wrongElement) throws Exception
  {
    var ci = mock(ContentInfo.class);
    var sd = mockValidSignedData(valid, wrongElement);
    when(ci.getContent()).thenReturn(sd);
    when(ci.getContentType()).thenReturn(new ASN1ObjectIdentifier(valid
      ? ContentInfoChecker.OID_PKCS7_SIGNEDDATA : "1.2.840.113549.3.2"));
    return ci;
  }

  @SuppressWarnings("boxing")
  private SignedData mockValidSignedData(boolean valid, boolean wrongElement) throws Exception
  {
    var signedData = mock(SignedData.class);
    when(signedData.getVersion()).thenReturn(new ASN1Integer(valid ? 3L : 4L));
    ASN1Set certSet = new DERSet(wrongElement ? mock(ASN1Integer.class) : mock(Certificate.class));
    ASN1Set revSet = new DERSet(mockRevocationFormat(valid, wrongElement));
    var singletonSet = mock(ASN1Set.class);
    when(singletonSet.size()).thenReturn(Integer.valueOf(1));
    ASN1Set emptySet = new DERSet();
    when(signedData.getCertificates()).thenReturn(valid ? certSet : emptySet);
    when(signedData.getCRLs()).thenReturn(revSet);

    var siSet = getSignerInfoSet(valid, wrongElement);
    when(signedData.getSignerInfos()).thenReturn(siSet);
    var mockEncapContenInfo = mockEncapContenInfo(wrongElement);
    when(signedData.getEncapContentInfo()).thenReturn(valid ? mockEncapContenInfo : null);
    ASN1Set digestSet = new DERSet(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3")));
    when(signedData.getDigestAlgorithms()).thenReturn(valid ? digestSet : emptySet);
    return signedData;
  }

  private ContentInfo mockEncapContenInfo(boolean wrongElement)
  {
    var encapContentInfo = mock(ContentInfo.class);
    when(encapContentInfo.getContentType()).thenReturn(new ASN1ObjectIdentifier(wrongElement
      ? ContentInfoChecker.OID_PKCS7_SIGNEDDATA : ContentInfoChecker.OID_TST_INFO));
    when(encapContentInfo.getContent()).thenReturn(new ASN1ObjectIdentifier(wrongElement
      ? ContentInfoChecker.OID_PKCS7_SIGNEDDATA : ContentInfoChecker.OID_TST_INFO));
    when(encapContentInfo.getContent()).thenReturn(wrongElement ? null : mock(TSTInfo.class));
    return encapContentInfo;
  }

  private ASN1TaggedObject mockRevocationFormat(boolean valid, boolean wrongElement)
  {
    var tag = mock(ASN1TaggedObject.class);
    var otherRevVector = new ASN1EncodableVector();
    otherRevVector.add(new ASN1ObjectIdentifier(wrongElement ? "1.3.3.7.1"
      : ContentInfoChecker.OID_BASIC_OSCP_RESPONSE));
    var mockOCSPResponse = mockOCSPResponse(valid);
    otherRevVector.add(wrongElement ? null : mockOCSPResponse);
    when(tag.getBaseObject()).thenReturn(new DLSequence(otherRevVector));
    return tag;
  }

  @SuppressWarnings("boxing")
  private BasicOCSPResponse mockOCSPResponse(boolean valid)
  {
    var ocspResp = mock(BasicOCSPResponse.class);
    ASN1Sequence sequence = when(mock(ASN1Sequence.class).size()).thenReturn(valid ? 1 : 0).getMock();
    when(ocspResp.getCerts()).thenReturn(sequence);
    ResponderID respID = when(mock(ResponderID.class).getName()).thenReturn(valid ? new X500Name("CN=test")
      : null).getMock();
    ResponseData respData = when(mock(ResponseData.class).getResponderID()).thenReturn(respID).getMock();
    Extensions singleExt = when(mock(Extensions.class).getExtension(ArgumentMatchers.any())).thenReturn(valid
      ? mock(Extension.class) : null).getMock();
    SingleResponse singleResp = when(mock(SingleResponse.class).getSingleExtensions()).thenReturn(singleExt)
                                                                                      .getMock();
    when(respData.getResponses()).thenReturn(new DERSequence(singleResp));
    when(ocspResp.getTbsResponseData()).thenReturn(respData);
    return ocspResp;
  }

  private ASN1Set getSignerInfoSet(boolean valid, boolean wrongElement) throws Exception
  {
    var si = mock(SignerInfo.class);
    when(si.getVersion()).thenReturn(new ASN1Integer(valid ? 1L : 4L));
    SignerIdentifier sid = when(mock(SignerIdentifier.class).getId()).thenReturn(valid
      ? mock(IssuerAndSerialNumber.class) : null).getMock();
    when(si.getSID()).thenReturn(sid);
    when(si.getDigestAlgorithm()).thenReturn(valid
      ? new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3")) : null);
    var signedAttributes = mockSignedAttributes(valid);
    when(si.getAuthenticatedAttributes()).thenReturn(signedAttributes);
    when(si.getEncryptedDigest()).thenReturn(valid ? new BEROctetString(new byte[0]) : null);
    when(si.getUnauthenticatedAttributes()).thenReturn(valid ? null
      : new BERSet(new DERUTF8String("Bad attribute")));
    return wrongElement ? new DERSet() : new DERSet(si);
  }

  @SuppressWarnings("boxing")
  private ASN1Set mockSignedAttributes(boolean valid) throws Exception
  {
    var saVector = new ASN1EncodableVector();
    saVector.add(new Attribute(new ASN1ObjectIdentifier(ContentInfoChecker.OID_CONTENT_TYPE),
                               new DERSet(new ASN1ObjectIdentifier(valid ? ContentInfoChecker.OID_TST_INFO
                                 : "1.2.3"))));
    saVector.add(new Attribute(new ASN1ObjectIdentifier(ContentInfoChecker.OID_MESSAGE_DIGEST),
                               valid ? new BERSet(new DERUTF8String("dummy")) : new BERSet()));
    SigningCertificateV2 scv2 = when(mock(SigningCertificateV2.class).getCerts()).thenReturn(new ESSCertIDv2[valid
      ? 1 : 0]).getMock();
    saVector.add(new Attribute(new ASN1ObjectIdentifier(ContentInfoChecker.OID_SIGNING_CERTIFICATTE_V2),
                               new BERSet(scv2)));
    if (!valid)
    {
      saVector.add(new Attribute(new ASN1ObjectIdentifier("1.2.3"), null));
      saVector.add(new Attribute(new ASN1ObjectIdentifier("1.2.3.4"), new BERSet())); // NOPMD no an IP but
      // some OID
    }
    var realSaSet = new BERSet(saVector);
    var saSet = valid ? mock(DERSet.class) : mock(ASN1Set.class);
    when(saSet.getEncoded(ASN1Encoding.DL)).thenReturn(new byte[0]);
    when(saSet.iterator()).thenReturn(realSaSet.iterator());
    when(saSet.size()).thenReturn(realSaSet.size());
    return saSet;
  }
}
