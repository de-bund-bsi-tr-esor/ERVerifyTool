package de.bund.bsi.tr_esor.checktool.xml;

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ECARD_EXT;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ESOR_VR;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ETSI;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ETSI_SVR;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_XAIP;

import java.io.IOException;
import java.util.List;

import javax.xml.namespace.QName;

import oasis.names.tc.dss._1_0.core.schema.SignatureObject;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.w3c.dom.Element;

import de.bund.bsi.tr_esor.checktool.Toolbox;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.xaip.CredentialType;
import de.bund.bsi.tr_esor.xaip.DataObjectType;
import de.bund.bsi.tr_esor.xaip.MetaDataObjectType;
import de.bund.bsi.tr_esor.xaip.VersionManifestType;


/**
 * XaipSerializer for cases where the Document is not available. Use ComprehensiveXaipSerializer where
 * possible.
 */
public class BasicXaipSerializer implements XaipSerializer
{

  private final String canonicalizationAlgo;

  private final LXaipReader lXaipReader;

  private final NamespaceMapper namespaceMapper;

  private static final String TR_ESOR_XAIP_1_3_NS = "http://www.bsi.bund.de/tr-esor/xaip";

  private static final QName VERSION_MANIFEST_QNAME = new QName(TR_ESOR_XAIP_1_3_NS, "versionManifest");

  private static final String CONTEXT_PATH = XmlHelper.FACTORY_XAIP.getClass().getPackage().getName();


  /**
   * Instances are created by the parser exclusively.
   */
  public BasicXaipSerializer(String canonicalizationAlgo, LXaipReader lXaipReader)
  {
    this.canonicalizationAlgo = canonicalizationAlgo;
    this.lXaipReader = lXaipReader;
    this.namespaceMapper = new NamespaceMapper(Configurator.getInstance().getXMLNSPrefixes());
  }

  /**
   * serialize using the canonicalization algorithm given in the xaip
   */
  @Override
  public byte[] serialize(Object value) throws JAXBException, InvalidCanonicalizerException,
    CanonicalizationException, IOException, IllegalArgumentException
  {
    Element element;
    if (value instanceof VersionManifestType)
    {
      var jaxbElement = new JAXBElement<>(VERSION_MANIFEST_QNAME, VersionManifestType.class, null,
                                          (VersionManifestType)value);
      element = XmlHelper.toElement(jaxbElement, CONTEXT_PATH, null);
      namespaceMapper.setNSPrefixRecursively(element);
    }
    else if (value instanceof CredentialType)
    {
      element = XmlHelper.toElement((CredentialType)value,
                                    CONTEXT_PATH,
                                    XmlHelper.FACTORY_XAIP::createCredential);
      namespaceMapper.setNSPrefixRecursively(element);
    }
    else if (value instanceof JAXBElement)
    {
      element = XmlHelper.toElement(value, CONTEXT_PATH, null);
    }
    else if (value instanceof Element)
    {
      element = (Element)value;
    }
    else
    {
      throw new IllegalArgumentException("Cannot serialize unknown data type: " + value.getClass());
    }

    return XmlHelper.canonicalizeSubtree(Canonicalizer.getInstance(canonicalizationAlgo), element);
  }

  @Override
  public byte[] serializeXmlSignatureFromCredential(String credentialId, SignatureObject sig)
    throws CanonicalizationException, InvalidCanonicalizerException, JAXBException, IOException
  {
    return serializeForSignatureVerification(sig);
  }

  @Override
  public byte[] serializeForSignatureVerification(Object value)
    throws IOException, JAXBException, InvalidCanonicalizerException, CanonicalizationException
  {
    if (value instanceof DataObjectType)
    {
      DataObjectType data = (DataObjectType)value;
      var binaryData = Toolbox.readBinaryData(lXaipReader, data);
      if (binaryData != null)
      {
        return binaryData;
      }
    }
    if (value instanceof MetaDataObjectType)
    {
      MetaDataObjectType meta = (MetaDataObjectType)value;
      var binaryData = Toolbox.readBinaryData(lXaipReader, meta);
      if (binaryData != null)
      {
        return binaryData;
      }
    }

    var packages = List.of(FACTORY_XAIP.getClass().getPackage().getName(),
                           FACTORY_ESOR_VR.getClass().getPackage().getName(),
                           FACTORY_ECARD_EXT.getClass().getPackage().getName(),
                           FACTORY_ETSI_SVR.getClass().getPackage().getName(),
                           FACTORY_ETSI.getClass().getPackage().getName());
    var contextPath = String.join(":", packages);
    var context = JAXBContext.newInstance(contextPath, BasicXaipSerializer.class.getClassLoader());
    var marshaller = context.createMarshaller();


    var node = marshaller.getNode(value);
    return XmlHelper.canonicalizeSubtree(Canonicalizer.getInstance(canonicalizationAlgo), node);
  }
}
