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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Basis-ERS-Profil validator for content info element from a RFC3161 time stamp.
 *
 * @author BVO, HMA, MO
 */
public class ContentInfoChecker
{

  private static final Logger LOG = LoggerFactory.getLogger(ContentInfoChecker.class);

  static final String OID_BASIC_OSCP_RESPONSE = "1.3.6.1.5.5.7.48.1.1";

  private static final String OID_CERT_HASH = "1.3.36.8.3.13";

  static final String OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";

  static final String OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

  static final String OID_PKCS7_SIGNEDDATA = "1.2.840.113549.1.7.2";

  static final String OID_SIGNING_CERTIFICATTE_V2 = "1.2.840.113549.1.9.16.2.47";

  static final String OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";

  private final List<AlgorithmIdentifier> digestIdentifiers = new ArrayList<>();

  private final FormatOkReport formatOk;

  /**
   * New content info checker with formatOk (result) to fill in case of a format error.
   *
   * @param formatOk
   */
  public ContentInfoChecker(FormatOkReport formatOk)
  {
    this.formatOk = formatOk;
  }

  /**
   * Verifies the given content info element.
   *
   * @param ref
   * @param contentInfo
   */
  public void checkContentInfo(Reference ref, ContentInfo contentInfo)
  {
    checkContentType(ref.newChild("contentType"), contentInfo.getContentType());
    Reference content = ref.newChild("content");
    SignedData sd = getInstanceOrFail(SignedData::getInstance, contentInfo.getContent(), content);
    if (sd != null)
    {
      checkSignedData(content, sd);
    }
  }

  private void checkContentType(Reference ref, ASN1ObjectIdentifier contentType)
  {
    if (!OID_PKCS7_SIGNEDDATA.equals(contentType.getId()))
    {
      formatOk.invalidate("contentType OID of time stamp is not " + OID_PKCS7_SIGNEDDATA, ref);
    }
  }

  /**
   * Checks the signed data element from a time stamp as specified in BSI TR-ESOR-ERS A3&#046;4-3. Note that
   * requirement A3.4-3(b), (c) and (d) from BSI TR-ESOR-ERS must be checked by eCard service.
   *
   * @param ref
   * @param signedData
   */
  void checkSignedData(Reference ref, SignedData signedData)
  {
    if (!new ASN1Integer(3L).equals(signedData.getVersion()))
    {
      formatOk.invalidate("version must be 3", ref.newChild("version"));
    }
    Reference digestAlgos = ref.newChild("digestAlgorithms");
    if (signedData.getDigestAlgorithms() == null || signedData.getDigestAlgorithms().size() == 0)
    {
      formatOk.invalidate("digestAlgorithms must be filled", digestAlgos);
    }
    else
    {
      int algoCount = 0;
      for ( ASN1Encodable algorithm : signedData.getDigestAlgorithms() )
      {
        digestIdentifiers.add(getInstanceOrFail(AlgorithmIdentifier::getInstance,
                                                algorithm,
                                                digestAlgos.newChild(Integer.toString(algoCount++))));
      }
    }
    checkEContentType(ref.newChild("encapContentInfo"), signedData.getEncapContentInfo());
    Reference certs = ref.newChild("certificates");
    if (signedData.getCertificates() == null || signedData.getCertificates().size() == 0)
    {
      formatOk.invalidate("certificates must be filled", certs);
    }
    else
    {
      checkCertificateSet(certs, signedData.getCertificates());
    }
    Reference crlRef = ref.newChild("crls");
    if (signedData.getCRLs() == null || signedData.getCRLs().size() == 0)
    {
      formatOk.invalidate("CRLs must be filled", crlRef);
    }
    else
    {
      checkRevocationInfoChoices(crlRef, signedData.getCRLs());
    }
    Reference siRef = ref.newChild("signerInfos");
    if (signedData.getSignerInfos() == null || signedData.getSignerInfos().size() != 1)
    {
      formatOk.invalidate("signerInfos must contain exactly one element", siRef);
    }
    else
    {
      checkSignerInfo(siRef.newChild("signerInfo"), signedData.getSignerInfos().iterator().next());
    }
  }

  /**
   * Checks the encapContentInfo element from SignedData as specified in BSI TR-ESOR-ERS A3&#046;4-4. Note
   * that requirement A3.4-4(c) from BSI TR-ESOR-ERS is done in the ArchiveTimeStampValidator.
   *
   * @param ref
   * @param contentInfo
   */
  private void checkEContentType(Reference ref, ContentInfo contentInfo)
  {
    if (contentInfo == null)
    {
      formatOk.invalidate("encapContentInfo must be filled", ref);
      return;
    }
    if (!OID_TST_INFO.equals(contentInfo.getContentType().getId()))
    {
      formatOk.invalidate("content-type must be " + OID_TST_INFO, ref.newChild("eContentType"));
    }
    if (contentInfo.getContent() == null)
    {
      formatOk.invalidate("content must be present and of type TSTInfo", ref.newChild("eContent"));
    }
  }

  /**
   * Checks the CertificateSet element from SignedData as specified in BSI TR-ESOR-ERS A3&#046;4-5 and -6.
   *
   * @param ref
   * @param certificateChoices
   */
  private void checkCertificateSet(Reference ref, ASN1Set certificateChoices)
  {
    Iterator<ASN1Encodable> choices = certificateChoices.iterator();
    for ( int certCount = 0 ; choices.hasNext() ; certCount++ )
    {
      Certificate cert = getInstance(Certificate::getInstance, choices.next());
      if (cert == null)
      {
        formatOk.invalidate("certificates must only contain elements of type Certificate",
                            ref.newChild(Integer.toString(certCount)));
      }
    }
  }

  /**
   * Checks the RevocationInfoChoice element from SignedData as specified in BSI TR-ESOR-ERS A3&#046;4-7 and
   * -8.
   *
   * @param ref
   * @param revocationInfoChoices
   */
  void checkRevocationInfoChoices(Reference ref, ASN1Set revocationInfoChoices)
  {
    Iterator<ASN1Encodable> choices = revocationInfoChoices.iterator();

    for ( int revCount = 0 ; choices.hasNext() ; revCount++ )
    {
      ASN1Encodable ric = choices.next();
      Reference revChoice = ref.newChild(Integer.toString(revCount));
      OtherRevocationInfoFormat orif = getInstance(this::extractOrif, ric);
      if (orif == null)
      {
        if (getInstance(CertificateList::getInstance, ric) == null)
        {
          formatOk.invalidate("RevocationInfoChoice must be either CertificateList or OtherRevocationInfoFormat",
                              revChoice);
        }
      }
      else
      {
        checkOrif(orif, revChoice);
      }
    }
  }

  private void checkOrif(OtherRevocationInfoFormat orif, Reference revChoice)
  {
    BasicOCSPResponse resp = getInstance(BasicOCSPResponse::getInstance, orif.getInfo());
    if (resp == null || !OID_BASIC_OSCP_RESPONSE.equals(orif.getInfoFormat().getId()))
    {
      formatOk.invalidate("OtherRevocationInfoFormat must contain a BasicOCSPResponse", revChoice);
      return;
    }
    if (resp.getCerts().size() == 0)
    {
      formatOk.invalidate("certs from BasicOCSPResponse must contain at least one element",
                          revChoice.newChild("certs"));
    }
    if (resp.getTbsResponseData().getResponderID().getName() == null)
    {
      formatOk.invalidate("ResponderID from BasicOCSPResponse must use byName choice",
                          revChoice.newChild("ResponseData").newChild("ResponderID"));
    }
    int respCount = 0;
    Iterator<ASN1Encodable> resps = resp.getTbsResponseData().getResponses().iterator();
    for ( SingleResponse singleResp ; resps.hasNext() ; respCount++ )
    {
      Reference singleRespRev = revChoice.newChild("ResponseData")
                                         .newChild("responses")
                                         .newChild(Integer.toString(respCount));
      singleResp = getInstanceOrFail(SingleResponse::getInstance, resps.next(), singleRespRev);
      if (singleResp != null && (singleResp.getSingleExtensions() == null
                                 || singleResp.getSingleExtensions()
                                              .getExtension(new ASN1ObjectIdentifier(OID_CERT_HASH)) == null))
      {
        formatOk.invalidate("SingleResponse must contain CertHash extension", singleRespRev);
      }
    }
  }

  private OtherRevocationInfoFormat extractOrif(Object obj)
  {
    Object orif = obj instanceof ASN1TaggedObject ? ((ASN1TaggedObject)obj).getObject() : null;
    return OtherRevocationInfoFormat.getInstance(orif);
  }

  /**
   * Checks the SignerInfo element from SignedData as specified in BSI TR-ESOR-ERS A3&#046;4-9.
   *
   * @param ref
   * @param asn1si
   */
  private void checkSignerInfo(Reference ref, ASN1Encodable asn1si)
  {
    SignerInfo si = getInstanceOrFail(SignerInfo::getInstance, asn1si, ref);
    if (si == null)
    {
      return;
    }
    if (!new ASN1Integer(1L).equals(si.getVersion()))
    {
      formatOk.invalidate("version must be 1", ref.newChild("version"));
    }
    if (si.getSID() == null || si.getSID().getId() == null
        || getInstance(IssuerAndSerialNumber::getInstance, si.getSID().getId()) == null)
    {
      formatOk.invalidate("sid must be of type IssuerAndSerialNumber", ref.newChild("sid"));
    }
    if (!digestIdentifiers.contains(si.getDigestAlgorithm()))
    {
      formatOk.invalidate("algorithm must be equal to one of SignedData.digestAlgorithms",
                          ref.newChild("digestAlgorithm"));
    }
    checkSignedAttributes(ref.newChild("signedAttrs"), si.getAuthenticatedAttributes());
    if (si.getDigestAlgorithm() == null)
    {
      formatOk.invalidate("signatureAlgorithm must be present", ref.newChild("signatureAlgorithm"));
    }
    if (si.getEncryptedDigest() == null)
    {
      formatOk.invalidate("signatureValue must be present", ref.newChild("signatureValue"));
    }
    if (si.getUnauthenticatedAttributes() != null && si.getUnauthenticatedAttributes().size() > 0)
    {
      formatOk.invalidate("unsignedAttrs must be omitted", ref.newChild("unsignedAttrs"));
    }
  }

  /**
   * Checks the SignedAttribute element from SignerInfo as specified in BSI TR-ESOR-ERS A3&#046;4-10.
   *
   * @param ref
   * @param attrs
   */
  private void checkSignedAttributes(Reference ref, ASN1Set attrs)
  {
    checkAttributesIsDERSet(ref, attrs);
    final int requiredAttributeCount = 3;
    if (attrs.size() != requiredAttributeCount)
    {
    	/*
      formatOk.invalidate("attribute set must contain exactly one content-type, message-digest and SigningCertificateV2 attribute",
                          ref.newChild("content"));
                          */
      formatOk.updateCodes(null,  null,  null, "attribute set does contain more signed attributes than reqired content-type, message-digest and SigningCertificateV2",
              ref.newChild("content"));
    }
    Iterator<ASN1Encodable> attributes = attrs.iterator();
    int attrCount = 0;
    for ( Attribute attr ; attributes.hasNext() ; attrCount++ )
    {
      attr = getInstance(Attribute::getInstance, attributes.next());
      if (attr == null)
      {
        continue;
      }
      if (attr.getAttrType() == null || attr.getAttrValues() == null)
      {
        formatOk.invalidate("attribute must contain a type and a value set",
                            ref.newChild(Integer.toString(attrCount)));
      }
      else
      {
        switch (attr.getAttrType().getId())
        {
          case OID_CONTENT_TYPE:
            checkContentTypeAttribute(ref.newChild("content-type"), attr);
            break;
          case OID_MESSAGE_DIGEST:
            checkMessageDigestAttribute(ref.newChild("message-digest"), attr);
            break;
          case OID_SIGNING_CERTIFICATTE_V2:
            checkSigningCertificateAttribute(ref.newChild("signing-certificate-v2"), attr);
            break;
          default:
            /*formatOk.invalidate("attribute with OID " + attr.getAttrType().getId() + " is not allowed",
                                ref.newChild(Integer.toString(attrCount)));*/
            formatOk.updateCodes(null, null, null, "signed attribute with OID " + attr.getAttrType().getId() + " is contained additionally",
                    ref.newChild(Integer.toString(attrCount)));
            break;
        }
      }
    }
  }

  /**
   * Checks if given attribute set is encoded with DER.
   *
   * @param ref
   * @param attrs
   */
  private void checkAttributesIsDERSet(Reference ref, ASN1Set attrs)
  {
    if (!(attrs instanceof DERSet))
    {
      boolean isEqualToDERSet = false;
      try
      {
        isEqualToDERSet = Arrays.equals(attrs.getEncoded(ASN1Encoding.DL),
                                        attrs.getEncoded(ASN1Encoding.DER));
      }
      catch (IOException e)
      {
        LOG.error("Error while parsing signed attributes", e);
      }
      if (!isEqualToDERSet)
      {
        formatOk.invalidate("attributes must be DER encoded", ref.newChild("asn1-encoding"));
      }
    }
  }

  /**
   * Checks the ContentType element from SignedAttribute as specified in BSI TR-ESOR-ERS A3&#046;4-11.
   *
   * @param ref
   * @param contentType
   */
  void checkContentTypeAttribute(Reference ref, Attribute contentType)
  {
    if (contentType.getAttrValues() == null || contentType.getAttrValues().size() != 1)
    {
      formatOk.invalidate("attribute must have a value set", ref);
      return;
    }
    ASN1ObjectIdentifier oid = getInstance(ASN1ObjectIdentifier::getInstance,
                                           contentType.getAttrValues().iterator().next());
    if (oid == null || !OID_TST_INFO.equals(oid.getId()))
    {
      formatOk.invalidate("content-type must be " + OID_TST_INFO, ref);
    }
  }

  /**
   * Checks the MessageDigest element from SignedAttribute as specified in BSI TR-ESOR-ERS A3&#046;4-12.
   *
   * @param ref
   * @param messageDigest
   */
  private void checkMessageDigestAttribute(Reference ref, Attribute messageDigest)
  {
    if (messageDigest.getAttrValues() == null || messageDigest.getAttrValues().size() != 1)
    {
      formatOk.invalidate("attribute must have a value set", ref);
    }
  }

  /**
   * Checks the SigningCertificateV2 element from SignedAttribute as specified in BSI TR-ESOR-ERS
   * A3&#046;4-13. Note that requirement A3.4-13(c) from BSI TR-ESOR-ERS must be checked by eCard service.
   *
   * @param ref
   * @param sigCert
   */
  void checkSigningCertificateAttribute(Reference ref, Attribute sigCert)
  {
    if (sigCert.getAttrValues() == null || sigCert.getAttrValues().size() != 1)
    {
      formatOk.invalidate("attribute must have a value set", ref);
      return;
    }
    SigningCertificateV2 sigCertInstance = getInstance(SigningCertificateV2::getInstance,
                                                       sigCert.getAttrValues().iterator().next());
    if (sigCertInstance == null)
    {
      formatOk.invalidate("attribute must be SigningCertificateV2", ref);
      return;
    }
    try
    {
      if (sigCertInstance.getCerts().length == 0)
      {
        formatOk.invalidate("SigningCertificateV2 must contain at least one ESSCertIDv2",
                            ref.newChild("ESSCertIDv2"));
      }
    }
    catch (IllegalArgumentException e)
    {
      LOG.debug("Could not parse ESSCertIDv2", e);
      formatOk.invalidate("ESSCertIDv2 reference is not conform to RFC5035", ref.newChild("ESSCertIDv2"));
    }

  }

  /**
   * Applies the given function to the input. If the function call was not successful, returns null.
   *
   * @param instanceFunc
   * @param input
   * @return
   */
  private <T> T getInstance(Function<Object, T> instanceFunc, Object input)
  {
    return getInstanceOrFail(instanceFunc, input, null);
  }

  /**
   * Applies the given function to the input. If the application fails or returns null, an invalid format
   * entry is generated using the given reference. If the reference is null, no invalid format entry is
   * generated.
   *
   * @param instanceFunc
   * @param input
   * @param ref
   * @return
   */
  private <T> T getInstanceOrFail(Function<Object, T> instanceFunc, Object input, Reference ref)
  {
    String errorMsg = "";
    try
    {
      T result = instanceFunc.apply(input);
      if (result != null)
      {
        return result;
      }
    }
    catch (IllegalArgumentException e)
    {
      LOG.debug("Could not parse element", e);
      errorMsg = ", error was: " + e.getMessage();
    }
    if (ref != null)
    {
      formatOk.invalidate("Could not parse element" + errorMsg, ref);
    }
    return null;
  }
}
