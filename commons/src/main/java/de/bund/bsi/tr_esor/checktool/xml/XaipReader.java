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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Element;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.xaip._1.CredentialType;
import de.bund.bsi.tr_esor.xaip._1.DataObjectType;
import de.bund.bsi.tr_esor.xaip._1.MetaDataObjectType;
import de.bund.bsi.tr_esor.xaip._1.PackageInfoUnitType;
import de.bund.bsi.tr_esor.xaip._1.VersionManifestType;
import de.bund.bsi.tr_esor.xaip._1.XAIPType;


/**
 * Utility class which reads a given XAIP and returns the protected Objects.
 *
 * @author BVO, KK
 */
public class XaipReader
{

  private static final String TR_ESOR_XAIP_1_2_NS = "http://www.bsi.bund.de/tr-esor/xaip/1.2";

  private final XAIPType xaip;

  private final Reference reference;

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
  public XaipReader(XAIPType xaip, Reference reference)
  {
    this.xaip = xaip;
    this.reference = reference;
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

  private Reference createRefForEr(CredentialType cred)
  {
    String cid = cred.getCredentialID();
    Reference ref = reference.newChild("evidenceRecord:" + cid);
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
   *
   * @param versionId
   * @throws JAXBException
   * @throws XMLSecurityException
   */
  public Map<Reference, byte[]> getProtectedElements(String versionId)
    throws JAXBException, XMLSecurityException
  {
    Map<Reference, byte[]> result = new HashMap<>();
    VersionManifestType manifest = getVersionManifest(versionId);
    List<JAXBElement<Object>> pointer = new ArrayList<>();
    addPointers(manifest.getPackageInfoUnit(), pointer);

    String algorithm = xaip.getPackageHeader().getCanonicalizationMethod().getAlgorithm();
    Canonicalizer canon = Canonicalizer.getInstance(algorithm);

    for ( JAXBElement<Object> p : pointer )
    {
      Element element = null;
      Reference id = null;
      Object value = p.getValue();

      if (value instanceof DataObjectType)
      {
        DataObjectType data = (DataObjectType)value;
        result.put(createRef("dataObjectID", data.getDataObjectID()), data.getBinaryData().getValue());
        continue;
      }
      if (value instanceof MetaDataObjectType)
      {
        MetaDataObjectType meta = (MetaDataObjectType)value;
        element = XmlHelper.toElement(meta, CONTEXT_PATH, XmlHelper.FACTORY_XAIP::createMetaDataObject);
        namespaceMapper.setNSPrefix(element);
        id = createRef("metaDataID", meta.getMetaDataID());
      }
      if (value instanceof CredentialType)
      {
        CredentialType cred = (CredentialType)value;
        element = XmlHelper.toElement(cred, CONTEXT_PATH, XmlHelper.FACTORY_XAIP::createCredential);
        namespaceMapper.setNSPrefixRecursively(element);
        id = createRef("credentialID", cred.getCredentialID());
      }
      if (value instanceof VersionManifestType)
      {
        VersionManifestType mani = (VersionManifestType)value;
        QName name = new QName(TR_ESOR_XAIP_1_2_NS, "versionManifest");
        JAXBElement<VersionManifestType> je = new JAXBElement<>(name, VersionManifestType.class, null, mani);
        element = XmlHelper.toElement(je, CONTEXT_PATH, null);
        namespaceMapper.setNSPrefixRecursively(element);
        id = createRef("versionID", mani.getVersionID());
      }

      if (id != null && element != null)
      {
        result.put(id, canon.canonicalizeSubtree(element));
      }
    }
    return result;
  }

  private Reference createRef(String attributeName, String id)
  {
    Reference ref = reference.newChild(attributeName + ":" + id);
    if (reference.getxPath() != null)
    {
      ref.setxPath(reference.getxPath() + "//*[@" + attributeName + "='" + id + "']");
    }
    return ref;
  }

  private void addPointers(List<PackageInfoUnitType> packageInfoUnit, List<JAXBElement<Object>> pointer)
  {
    for ( PackageInfoUnitType info : packageInfoUnit )
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
               .orElseThrow(() -> new IllegalArgumentException("unknown versionID"));
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

}
