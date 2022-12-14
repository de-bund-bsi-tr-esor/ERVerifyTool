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
package de.bund.bsi.tr_esor.checktool.xml;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import oasis.names.tc.dss._1_0.core.schema.SignatureObject;

import jakarta.xml.bind.JAXBException;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import de.bund.bsi.tr_esor.checktool.Toolbox;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.xaip.CredentialType;
import de.bund.bsi.tr_esor.xaip.DataObjectType;
import de.bund.bsi.tr_esor.xaip.MetaDataObjectType;
import de.bund.bsi.tr_esor.xaip.VersionManifestType;


/**
 * Serializes XAIP elements for creating hash values. <br>
 * WARNING: Note that for each serialization this class has to create a new instance of {@link Canonicalizer}
 * because that one might produce incorrect output when used more than once.
 *
 * @author TT
 */
public class ComprehensiveXaipSerializer implements XaipSerializer
{

  private final String canonicalizationAlgo;

  private final Document xaip;

  private final LXaipReader lXaipReader;

  private final boolean rewriteNamespaces;

  private static final TransformerFactory TRANSFORMER_FACTORY = TransformerFactory.newInstance();

  static
  {
    if (!Init.isInitialized())
    {
      Init.init();
    }
  }

  /**
   * Instances are created by the parser exclusively.
   */
  public ComprehensiveXaipSerializer(Document xaip, String canonicalizationAlgo, LXaipReader lXaipReader)
  {
    Objects.requireNonNull(xaip, "DOM document containg the XAIP");
    this.canonicalizationAlgo = canonicalizationAlgo;
    this.xaip = xaip;
    this.lXaipReader = lXaipReader;
    this.rewriteNamespaces = false;
  }

  /**
   * Instances are created by the parser exclusively.
   */
  public ComprehensiveXaipSerializer(Document xaip,
                                     String canonicalizationAlgo,
                                     LXaipReader lXaipReader,
                                     boolean rewriteNamespaces)
  {
    Objects.requireNonNull(xaip, "DOM document containg the XAIP");
    this.canonicalizationAlgo = canonicalizationAlgo;
    this.xaip = xaip;
    this.lXaipReader = lXaipReader;
    this.rewriteNamespaces = rewriteNamespaces;
  }

  /**
   * Returns the serialized signature as-is from given credentials SignatureObject.
   */
  @Override
  public byte[] serializeXmlSignatureFromCredential(String credentialId, SignatureObject sig)
    throws TransformerException
  {
    var credNode = getNodeByLocalNameAndId(xaip, "credential", "credentialID", credentialId);
    var sigNode = getNodeByLocalNameAndId(credNode, "Signature", null, null);

    return toBytes(sigNode);
  }

  private static byte[] toBytes(Node node) throws TransformerException
  {
    var transformer = TRANSFORMER_FACTORY.newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    var result = new StreamResult(new ByteArrayOutputStream());
    transformer.transform(new DOMSource(node), result);
    return ((ByteArrayOutputStream)result.getOutputStream()).toByteArray();
  }

  private static Canonicalizer canonicalizer(String algo) throws InvalidCanonicalizerException
  {
    return Canonicalizer.getInstance(algo);
  }


  /**
   * serialize using the canonicalization algorithm given in the xaip
   */
  public byte[] serialize(Object value)
    throws CanonicalizationException, JAXBException, InvalidCanonicalizerException, IOException
  {
    return serialize(value, canonicalizer(canonicalizationAlgo));
  }

  /**
   * Returns the serialized form of the XAIP element for hash creation.
   *
   * @param value must be a data object, meta, credential or manifest
   */
  @SuppressWarnings("PMD.DataflowAnomalyAnalysis")
  private byte[] serialize(Object value, Canonicalizer can) throws CanonicalizationException, IOException
  {
    Node elem = null;
    if (value instanceof DataObjectType)
    {
      var data = (DataObjectType)value;
      var binaryData = Toolbox.readBinaryData(lXaipReader, data);
      if (binaryData != null)
      {
        return binaryData;
      }
      if (data.getXmlData() == null)
      {
        throw new IllegalArgumentException("Data objects must contain either base64 binary or xml data");
      }
      elem = getNodeByLocalNameAndId(xaip, "dataObject", "dataObjectID", data.getDataObjectID());
      // we use the whole xmlData object because TR-ESOR does not specify otherwise
      elem = getNodeByLocalNameAndId(elem, "xmlData", null, null);
      elem = onlyChildElementOrThrow(elem.getChildNodes(), data.getDataObjectID());
    }
    if (value instanceof MetaDataObjectType)
    {
      var meta = (MetaDataObjectType)value;
      elem = getNodeByLocalNameAndId(xaip, "metaDataObject", "metaDataID", meta.getMetaDataID());
    }
    if (value instanceof CredentialType)
    {
      var cred = (CredentialType)value;
      elem = getNodeByLocalNameAndId(xaip, "credential", "credentialID", cred.getCredentialID());
    }
    if (value instanceof VersionManifestType)
    {
      var mani = (VersionManifestType)value;
      elem = getNodeByLocalNameAndId(xaip, "versionManifest", "VersionID", mani.getVersionID());
    }
    if (elem == null)
    {
      throw new IllegalArgumentException("Unsupported type " + value.getClass().getName());
    }

    if (rewriteNamespaces && elem instanceof Element)
    {
      var namespaceMapper = new NamespaceMapper(Configurator.getInstance().getXMLNSPrefixes());
      namespaceMapper.setNSPrefixRecursively((Element)elem);
    }

    return XmlHelper.canonicalizeSubtree(can, elem);
  }

  /**
   * Serialize a XAIP element for signature verification. This explicitly only gives the content of a metadata
   * item.
   *
   * @param value dataObject, metaDataObject or credentialObject
   * @return content of the element serialized as byte[]
   */
  @Override
  public byte[] serializeForSignatureVerification(Object value)
    throws CanonicalizationException, InvalidCanonicalizerException, IOException
  {
    if (value instanceof MetaDataObjectType)
    {
      var meta = (MetaDataObjectType)value;
      var binaryData = Toolbox.readBinaryData(lXaipReader, meta);
      if (binaryData != null)
      {
        return binaryData;
      }
      if (meta.getXmlMetaData() != null)
      {
        var metaNode = getNodeByLocalNameAndId(xaip, "metaDataObject", "metaDataID", meta.getMetaDataID());
        if (hasChildElements(metaNode))
        {
          var xmlNode = getNodeByLocalNameAndId(metaNode, "xmlMetaData", null, null);
          var onlyChild = onlyChildElementOrThrow(xmlNode.getChildNodes(), meta.getMetaDataID());
          return XmlHelper.canonicalizeSubtree(canonicalizer(canonicalizationAlgo), onlyChild);
        }
        else
        {
          return metaNode.getTextContent().getBytes(StandardCharsets.UTF_8);
        }
      }
    }

    return serialize(value, canonicalizer(canonicalizationAlgo));
  }

  private boolean hasChildElements(Node node)
  {
    var childNodes = node.getChildNodes();
    for ( var i = 0 ; i < childNodes.getLength() ; i++ )
    {
      if (childNodes.item(i) instanceof Element)
      {
        return true;
      }
    }
    return false;
  }

  private static Node onlyChildElementOrThrow(NodeList children, String objectID)
  {
    Node exclusiveElement = null;
    for ( var i = 0 ; i < children.getLength() ; i++ )
    {
      if (children.item(i) instanceof Element)
      {
        if (exclusiveElement != null)
        {
          throw new IllegalArgumentException("The signed data object '" + objectID
                                             + "' has an xmlData element with more than one one child node");
        }
        exclusiveElement = children.item(i);
      }
    }
    if (exclusiveElement == null)
    {
      throw new IllegalArgumentException("The signed data object '" + objectID
                                         + "' has an xmlData element with no child nodes");
    }
    return exclusiveElement;
  }

  private static Node getNodeByLocalNameAndId(Document xaip, String localName, String idAttribute, String id)
  {
    return getNodeByLocalNameAndId(xaip.getDocumentElement(), localName, idAttribute, id);
  }

  private static Node getNodeByLocalNameAndId(Node node, String localName, String idAttribute, String id)
  {
    if (localName.equals(node.getLocalName()) && (idAttribute == null || hasAttribute(node, idAttribute, id)))
    {
      return node;
    }
    var children = node.getChildNodes();
    for ( var i = 0 ; i < children.getLength() ; i++ )
    {
      if (children.item(i).getNodeType() == Node.ELEMENT_NODE)
      {
        var result = getNodeByLocalNameAndId(children.item(i), localName, idAttribute, id);
        if (result != null)
        {
          return result;
        }
      }
    }
    return null;
  }

  private static boolean hasAttribute(Node node, String idAttribute, String id)
  {
    return Optional.ofNullable(node.getAttributes())
                   .map(attrs -> attrs.getNamedItem(idAttribute))
                   .map(Node::getTextContent)
                   .filter(id::equals)
                   .isPresent();
  }
}
