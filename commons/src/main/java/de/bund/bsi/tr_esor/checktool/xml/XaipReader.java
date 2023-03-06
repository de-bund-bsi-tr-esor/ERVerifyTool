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
package de.bund.bsi.tr_esor.checktool.xml;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import oasis.names.tc.dss._1_0.core.schema.Base64Signature;
import oasis.names.tc.dss._1_0.core.schema.SignatureObject;
import oasis.names.tc.dss._1_0.core.schema.Timestamp;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.etsi.uri._01903.v1_3.CRLValuesType;
import org.etsi.uri._01903.v1_3.CertificateValuesType;
import org.etsi.uri._01903.v1_3.EncapsulatedPKIDataType;
import org.etsi.uri._01903.v1_3.OCSPValuesType;
import org.etsi.uri._01903.v1_3.RevocationValuesType;

import de.bund.bsi.tr_esor.checktool.Toolbox;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.data.InlineSignedData;
import de.bund.bsi.tr_esor.checktool.data.InlineSignedDataObject;
import de.bund.bsi.tr_esor.checktool.data.InlineSignedMetaDataObject;
import de.bund.bsi.tr_esor.checktool.validation.VersionNotFoundException;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.xaip.CredentialType;
import de.bund.bsi.tr_esor.xaip.CredentialsSectionType;
import de.bund.bsi.tr_esor.xaip.DataObjectType;
import de.bund.bsi.tr_esor.xaip.EvidenceRecordType;
import de.bund.bsi.tr_esor.xaip.MetaDataObjectType;
import de.bund.bsi.tr_esor.xaip.PackageInfoUnitType;
import de.bund.bsi.tr_esor.xaip.VersionManifestType;
import de.bund.bsi.tr_esor.xaip.XAIPType;


/**
 * Utility class which reads a given XAIP and returns the protected Objects.
 *
 * @author BVO, KK
 */
public class XaipReader
{

  private static final String TR_ESOR_XAIP_1_3_NS = "http://www.bsi.bund.de/tr-esor/xaip";

  private final XAIPType xaip;

  private final Reference reference;

  private final String profileName;

  private final NamespaceMapper namespaceMapper;

  private static final String CONTEXT_PATH = XmlHelper.FACTORY_XAIP.getClass().getPackage().getName();

  static
  {
    if (!Init.isInitialized())
    {
      Init.init();
    }
  }

  /**
   * Create a new reader instance for XAIP.
   */
  public XaipReader(XAIPType xaip, Reference reference, String profileName)
  {
    this.xaip = xaip;
    this.reference = reference;
    this.profileName = profileName;
    this.namespaceMapper = new NamespaceMapper(Configurator.getInstance().getXMLNSPrefixes());
  }

  /**
   * Returns all evidence records of the current XAIP.
   */
  public Map<Reference, CredentialType> getEvidenceRecords()
  {
    if (xaip.getCredentialsSection() == null)
    {
      return Collections.emptyMap();
    }
    return xaip.getCredentialsSection()
               .getCredential()
               .stream()
               .filter(cred -> cred.getEvidenceRecord() != null)
               .collect(Collectors.toMap(this::createRefForEr, Function.identity()));
  }

  /** List of all data and meta data objects not covered by detached signatures */
  public List<InlineSignedData> findPotentiallyInlineSignedElements()
  {
    var results = new ArrayList<InlineSignedData>();
    var dataSection = xaip.getDataObjectsSection();
    var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory(profileName));

    if (dataSection != null)
    {
      for ( var data : dataSection.getDataObject() )
      {
        if ((lXaipReader.isValidLXaipElement(data, data.getDataObjectID()) || data.getBinaryData() != null))
        {
          results.add(new InlineSignedDataObject(new Reference(data.getDataObjectID()), lXaipReader, data));
        }
      }
    }

    var metaDataSection = xaip.getMetaDataSection();

    if (metaDataSection != null)
    {
      for ( var meta : metaDataSection.getMetaDataObject() )
      {
        if ((lXaipReader.isValidLXaipElement(meta, meta.getMetaDataID()) || meta.getBinaryMetaData() != null))
        {
          results.add(new InlineSignedMetaDataObject(new Reference(meta.getMetaDataID()), lXaipReader, meta));
        }
      }
    }
    return results;
  }

  /** List all credentials that contain signatures */
  public List<CredentialType> findDetachedSignatures()
  {
    var results = new ArrayList<CredentialType>();
    CredentialsSectionType credentialSection = xaip.getCredentialsSection();
    if (credentialSection == null)
    {
      return List.of();
    }

    var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory(profileName));
    for ( CredentialType cred : credentialSection.getCredential() )
    {
      if (lXaipReader.isValidLXaipElement(cred, cred.getCredentialID())
          || cred.getSignatureObject() != null && isSupportedSignatureObject(cred.getSignatureObject()))
      {
        results.add(cred);
      }
    }
    return results;
  }

  private boolean isSupportedSignatureObject(SignatureObject sigObj)
  {
    return sigObj.getBase64Signature() != null || sigObj.getSignature() != null
           || sigObj.getTimestamp() != null;
  }



  private boolean hasDetachedSignature(Object data)
  {
    return xaip.getCredentialsSection() != null && xaip.getCredentialsSection()
                                                       .getCredential()
                                                       .stream()
                                                       .map(CredentialType::getRelatedObjects)
                                                       .anyMatch(ro -> ro.contains(data));
  }

  private Reference createRefForEr(CredentialType cred)
  {
    var cid = cred.getCredentialID();
    var ref = reference.newChild("evidenceRecord:" + cid);
    if (reference.getxPath() != null)
    {
      ref.setxPath(reference.getxPath() + "/credentialSection/credential[@credentialID='" + cid
                   + "']/evidenceRecord/asn1EvidenceRecord");
    }
    return ref;
  }

  /**
   * Returns a map containing all protected elements of the specified version represented as canonicalized
   * byte arrays. Key is respective ID.
   */
  public Map<Reference, byte[]> prepareProtectedElements(String versionId, XaipSerializer serializer)
    throws JAXBException, XMLSecurityException, IOException
  {
    Map<Reference, byte[]> result = new HashMap<>();
    var manifest = getVersionManifest(versionId);
    List<JAXBElement<Object>> pointer = new ArrayList<>();
    addPointers(manifest.getPackageInfoUnit(), pointer);

    var algorithm = xaip.getPackageHeader().getCanonicalizationMethod().getAlgorithm();
    var canon = Canonicalizer.getInstance(algorithm);
    var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory(profileName));

    for ( var p : pointer )
    {
      Reference id = null;
      var value = p.getValue();

      if (value instanceof DataObjectType)
      {
        var data = (DataObjectType)value;
        var binaryData = Toolbox.readBinaryData(lXaipReader, data);
        result.put(createRef("dataObjectID", data.getDataObjectID()), binaryData);
        continue;
      }
      if (value instanceof MetaDataObjectType)
      {
        var meta = (MetaDataObjectType)value;
        var binaryData = Toolbox.readBinaryData(lXaipReader, meta);
        if (binaryData != null)
        {
          result.put(createRef("metaDataID", meta.getMetaDataID()), binaryData);
          continue;
        }
        else
        {
          id = createRef("metaDataID", meta.getMetaDataID());
        }
      }
      if (value instanceof CredentialType)
      {
        id = createRef("credentialID", ((CredentialType)value).getCredentialID());
        result.put(id, handleCredentialForHashing((CredentialType)value, canon, serializer));
        continue;
      }
      if (value instanceof VersionManifestType)
      {
        var mani = (VersionManifestType)value;
        id = createRef("versionID", mani.getVersionID());
      }
      if (value instanceof EncapsulatedPKIDataType)
      {
        id = createRef("EncapsulatedPKIData", ((EncapsulatedPKIDataType)value).getId());
        result.put(id, ((EncapsulatedPKIDataType)value).getValue());
        continue;
      }

      if (id != null)
      {
        result.put(id, serializer.serialize(value));
      }
    }
    return result;
  }

  private byte[] handleCredentialForHashing(CredentialType cred,
                                            Canonicalizer canon,
                                            XaipSerializer serializer)
    throws JAXBException, CanonicalizationException, IOException, InvalidCanonicalizerException
  {
    var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory(profileName));
    if (lXaipReader.isValidLXaipElement(cred, cred.getCredentialID()))
    {
      return lXaipReader.readBinaryData(cred, cred.getCredentialID());
    }
    // This is the formats that have a binary content
    // RFC3161 TimeStamp as signature
    var timestamp = Optional.ofNullable(cred.getSignatureObject())
                            .map(SignatureObject::getTimestamp)
                            .map(Timestamp::getRFC3161TimeStampToken);
    if (timestamp.isPresent())
    {
      return timestamp.get();
    }

    // encoded Signature (e.g. CMS)
    var encodedSignature = Optional.ofNullable(cred.getSignatureObject())
                                   .map(SignatureObject::getBase64Signature)
                                   .map(Base64Signature::getValue);
    if (encodedSignature.isPresent())
    {
      return encodedSignature.get();
    }

    // encapsulated X509 certificate
    var certs = Optional.ofNullable(cred.getCertificateValues())
                        .map(CertificateValuesType::getEncapsulatedX509CertificateOrOtherCertificate);
    if (certs.isPresent())
    {
      return handleCertificates(cred, certs.get(), canon);
    }

    // CRL Values
    var crl = Optional.ofNullable(cred.getRevocationValues())
                      .map(RevocationValuesType::getCRLValues)
                      .map(CRLValuesType::getEncapsulatedCRLValue);
    if (crl.isPresent())
    {
      if (crl.get().size() != 1)
      {
        throw new IllegalArgumentException("The credential " + cred.getCredentialID()
                                           + " does not contain exactly one CRL. The hash value can not be generated.");
      }
      return crl.get().get(0).getValue();
    }

    // OSCP Values
    var ocsp = Optional.ofNullable(cred.getRevocationValues())
                       .map(RevocationValuesType::getOCSPValues)
                       .map(OCSPValuesType::getEncapsulatedOCSPValue);
    if (ocsp.isPresent())
    {
      if (ocsp.get().size() != 1)
      {
        throw new IllegalArgumentException("The credential " + cred.getCredentialID()
                                           + " does not contain exactly one OCSP value. The hash value can not be generated.");
      }
      return ocsp.get().get(0).getValue();
    }
    // ASN.1 Evidence Record
    var er = Optional.ofNullable(cred.getEvidenceRecord()).map(EvidenceRecordType::getAsn1EvidenceRecord);
    if (er.isPresent())
    {
      return er.get();
    }

    return serializer.serialize(cred);
  }

  private byte[] handleCertificates(CredentialType cred, List<Object> certs, Canonicalizer canon)
    throws JAXBException, CanonicalizationException, IOException
  {
    var numberOfBinaryCertificates = certs.stream().filter(EncapsulatedPKIDataType.class::isInstance).count();
    if (numberOfBinaryCertificates > 1)
    {
      throw new IllegalArgumentException("The credential " + cred.getCredentialID()
                                         + " contains more than one certificate. The hash value can not be generated.");
    }
    if (numberOfBinaryCertificates == certs.size())
    {
      var cert = (EncapsulatedPKIDataType)certs.get(0);
      return cert.getValue();
    }
    if (numberOfBinaryCertificates != 0)
    {
      throw new IllegalArgumentException("The credential " + cred.getCredentialID()
                                         + " contains a mix of encapsulated and other certificate values. The hash value can not be generated.");
    }

    var element = XmlHelper.toElement(cred, CONTEXT_PATH, XmlHelper.FACTORY_XAIP::createCredential);
    namespaceMapper.setNSPrefixRecursively(element);
    return XmlHelper.canonicalizeSubtree(canon, element);
  }

  private Reference createRef(String attributeName, String id)
  {
    var ref = reference.newChild(attributeName + ":" + id);
    if (reference.getxPath() != null)
    {
      ref.setxPath(reference.getxPath() + "//*[@" + attributeName + "='" + id + "']");
    }
    return ref;
  }

  private void addPointers(List<PackageInfoUnitType> packageInfoUnit, List<JAXBElement<Object>> pointer)
  {
    for ( var info : packageInfoUnit )
    {
      pointer.addAll(info.getProtectedObjectPointer());
      addPointers(info.getPackageInfoUnit(), pointer);
    }
  }

  private VersionManifestType getVersionManifest(String versionId)
  {
    return xaip.getPackageHeader()
               .getVersionManifest()
               .stream()
               .filter(man -> man.getVersionID().equals(versionId))
               .findAny()
               .orElseThrow(() -> new VersionNotFoundException(versionId, listVersions()));
  }

  public String getAoid()
  {
    return xaip.getPackageHeader().getAOID();
  }

  /**
   * Returns version of the XAIP.
   */
  public String getVersion()
  {
    return xaip.getPackageHeader()
               .getVersionManifest()
               .stream()
               .map(VersionManifestType::getVersionID)
               .sorted((a, b) -> b.compareTo(a))
               .findFirst()
               .orElse(null);
  }

  /**
   * List all versions available in the XAIP-container.
   */
  public List<String> listVersions()
  {
    return xaip.getPackageHeader()
               .getVersionManifest()
               .stream()
               .map(VersionManifestType::getVersionID)
               .collect(Collectors.toList());
  }
}
