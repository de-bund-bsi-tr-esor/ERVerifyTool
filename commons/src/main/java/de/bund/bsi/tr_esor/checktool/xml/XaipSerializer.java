package de.bund.bsi.tr_esor.checktool.xml;

import java.io.IOException;

import javax.xml.transform.TransformerException;

import oasis.names.tc.dss._1_0.core.schema.SignatureObject;

import jakarta.xml.bind.JAXBException;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;


/**
 * Serializer to be used for XML structures inside of XAIPs
 */
public interface XaipSerializer
{

  /**
   * Serialize using the canonicalization algorithm given in the XAIP
   */
  byte[] serialize(Object value)
    throws JAXBException, InvalidCanonicalizerException, CanonicalizationException, IOException;


  /**
   * Returns the serialized signature as-is from given credentials SignatureObject.
   *
   * @return content of the element serialized as byte[]
   */
  byte[] serializeXmlSignatureFromCredential(String credentialId, SignatureObject sig)
    throws TransformerException, CanonicalizationException, InvalidCanonicalizerException, JAXBException,
    IOException;

  /**
   * Serialize a XAIP element for signature verification. This explicitly only gives the content of a metadata
   * item.
   *
   * @param value dataObject, metaDataObject or credentialObject
   * @return content of the element serialized as byte[]
   */
  byte[] serializeForSignatureVerification(Object value)
    throws CanonicalizationException, InvalidCanonicalizerException, IOException, JAXBException;
}
