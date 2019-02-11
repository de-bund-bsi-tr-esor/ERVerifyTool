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
package de.bund.bsi.tr_esor.checktool.entry;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.transform.dom.DOMSource;

import org.bouncycastle.cms.CMSSignedData;
import org.w3c.dom.Element;

import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ParserFactory;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.xaip._1.EvidenceRecordType;
import de.bund.bsi.tr_esor.xaip._1.XAIPType;
import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.Base64Signature;
import oasis.names.tc.dss._1_0.core.schema.DocumentType;
import oasis.names.tc.dss._1_0.core.schema.VerifyRequest;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;


/**
 * Implementation of {@link ParameterFinder} for input as web service verify request. Supported are:
 * <ul>
 * <li>one XAIP as inline XML or base 64 value, may contain evidence records or</li>
 * <li>an arbitrary number of secured binary contents (not interpreted)</li>
 * </ul>
 * as well as one SignatureObject which may be
 * <ul>
 * <li>a CMS signed data containing embedded evidence records or
 * <li>
 * <li>an ASN.1 evidence record. or</li>
 * </ul>
 *
 * @author HMA, TT
 */
public class WSParameterFinder extends ParameterFinder
{

  private static final String DETACHED_ER_ID = "detachedER";
  private static final String VR_NAMESPACE = "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#";

  /**
   * Creates instance to find data in given request.
   *
   * @param request object as parsed by the web service, i.e. contents of xs:any elements are still generic
   *          elements
   * @throws JAXBException
   */
  public WSParameterFinder(VerifyRequest request) throws JAXBException
  {
    setProfileName(request.getProfile());
    handleReturnVr(request);
    if (request.getInputDocuments() != null)
    {
      handleInputDocuments(request);
    }
    if (request.getSignatureObject() != null)
    {
      if (request.getSignatureObject().getBase64Signature() == null)
      {
        handleOther(request.getSignatureObject().getOther());
      }
      else
      {
        handleBase64Signature(request.getSignatureObject().getBase64Signature());
      }
    }
  }

  private void handleReturnVr(VerifyRequest request) throws JAXBException
  {
    String contextPath = XmlHelper.FACTORY_ESOR_VR.getClass().getPackage().getName();
    if (request.getOptionalInputs() != null)
    {
      for ( Object any : request.getOptionalInputs().getAny() )
      {
        if (any instanceof ReturnVerificationReport)
        {
          returnVerificationReport = (ReturnVerificationReport)any;
        }
        if (any instanceof Element)
        {
          Element element = (Element)any;
          if (VR_NAMESPACE.equals(element.getNamespaceURI())
              && "ReturnVerificationReport".equals(element.getLocalName()))
          {
            returnVerificationReport = XmlHelper.parse(new DOMSource(element),
                                                       ReturnVerificationReport.class,
                                                       contextPath);
          }
        }
      }
    }
  }

  private void handleOther(AnyType other)
  {
    if (other != null && !other.getAny().isEmpty())
    {
      EvidenceRecordType erXml = getErXML(other.getAny().get(0));
      try
      {
        er = new ASN1EvidenceRecordParser().parse(erXml.getAsn1EvidenceRecord());
        erRef = new Reference(DETACHED_ER_ID);
        erRef.setxPath("SignatureObject/Other/evidenceRecord/asn1EvidenceRecord");
        xaipVersionAddressdByEr = erXml.getVersionID();
        xaipAoidAddressdByEr = erXml.getAOID();
        return;
      }
      catch (IOException e)
      {
        throw new IllegalArgumentException("invalid content in element xaip:evidenceRecord", e);
      }
    }
    throw new IllegalArgumentException("only Base64Signature or other/evidenceRecord/asn1EvidenceRecord are supported");
  }

  private EvidenceRecordType getErXML(Object element)
  {
    if (element instanceof Element)
    {
      Element elem = (Element)element;
      if ("evidenceRecord".equals(elem.getLocalName())
          && "http://www.bsi.bund.de/tr-esor/xaip/1.2".equals(elem.getNamespaceURI()))
      {
        try
        {
          return XmlHelper.parse(new DOMSource(elem),
                                 EvidenceRecordType.class,
                                 XmlHelper.FACTORY_XAIP.getClass().getPackage().getName());
        }
        catch (JAXBException e)
        {
          throw new IllegalArgumentException("invalid content in element xaip:evidenceRecord", e);
        }
      }
    }
    else if (element instanceof JAXBElement<?>
             && ((JAXBElement<?>)element).getValue() instanceof EvidenceRecordType)
    {
      return (EvidenceRecordType)((JAXBElement<?>)element).getValue();
    }
    throw new IllegalArgumentException("unsupported content of other, expected xaip:evidenceRecord");
  }

  private void handleBase64Signature(Base64Signature base64Signature)
  {
    // Maybe using that field as well: request.getSignatureObject().getBase64Signature().getType()
    try (InputStream ins = new ByteArrayInputStream(base64Signature.getValue()))
    {
      Object parsed = ParserFactory.parse(ins, getProfileName());
      String xPath = "SignatureObject/Base64Signature/Value";
      if (parsed instanceof CMSSignedData)
      {
        cmsDocument = (CMSSignedData)parsed;
        cmsRef = new Reference("CmsSignature");
        cmsRef.setxPath(xPath);
      }
      else if (parsed instanceof XAIPType)
      {
        Reference xr = new Reference("XAIP");
        xr.setxPath(xPath);
        setXaipAttributes((XAIPType)parsed, xr);
      }
      else if (parsed instanceof EvidenceRecord)
      {
        erRef = new Reference(DETACHED_ER_ID);
        erRef.setxPath(xPath);
        er = (EvidenceRecord)parsed;
      }
      else if (parsed instanceof EvidenceRecordType)
      {
        erRef = new Reference(DETACHED_ER_ID);
        erRef.setxPath("/evidenceRecord/asn1EvidenceRecord");
        er = new ASN1EvidenceRecordParser().parse(((EvidenceRecordType)parsed).getAsn1EvidenceRecord());
        xaipVersionAddressdByEr = ((EvidenceRecordType)parsed).getVersionID();
      }
      else
      {
        unsupportedRef = new Reference("unsupportedSignatureObject");
        unsupportedRef.setxPath(xPath);
      }
    }
    catch (IOException e)
    {
      throw new IllegalArgumentException("Internal error parsing input", e);
    }
  }

  private void handleInputDocuments(VerifyRequest request) throws JAXBException
  {
    int numberDoc = 0;
    for ( Object doc : request.getInputDocuments().getDocumentOrTransformedDataOrDocumentHash() )
    {
      numberDoc++;
      if (!(doc instanceof DocumentType))
      {
        throw new IllegalArgumentException("only Documents supported as input");
      }
      DocumentType document = (DocumentType)doc;
      if (document.getInlineXML() != null) // NOPMD: searching for the one non-null element
      {
        setXaipAttributes(getXAIPXML(document.getInlineXML().getAny()),
                          createRefForDocument("XAIP", document.getID(), numberDoc, "/InlineXML"));
      }
      else if (document.getBase64Data() != null) // NOPMD: searching for the one non-null element
      {
        Reference ref = createRefForDocument("Bin" + numberDoc,
                                             document.getID(),
                                             numberDoc,
                                             "/Base64Data/Value");
        binaryDocuments.put(ref, document.getBase64Data().getValue());
      }
      else
      {
        throw new IllegalArgumentException("only Base64Data or InlineXML is supported in a Document");
      }
    }
  }

  private XAIPType getXAIPXML(Object element) throws JAXBException
  {
    if (element instanceof Element)
    {
      Element elem = (Element)element;
      return XmlHelper.parseXaip(elem);
    }
    if (element instanceof JAXBElement && ((JAXBElement<?>)element).getValue() instanceof XAIPType)
    {
      return (XAIPType)((JAXBElement<?>)element).getValue();
    }
    throw new IllegalArgumentException("InlineXML could not be parsed as XAIP");
  }

  private void setXaipAttributes(XAIPType parsed, Reference ref)
  {
    if (xaip != null)
    {
      throw new IllegalArgumentException("only one XAIP per request is supported");
    }
    xaip = parsed;
    xaipRef = ref;
  }


  private Reference createRefForDocument(String name, String docId, int numberDoc, String subPath)
  {
    Reference result = new Reference(name);
    String docPart = docId == null ? "Document[" + numberDoc + "]" : "Document[@id='" + docId + "']";
    result.setxPath("VerifyRequest/InputDocuments/" + docPart + subPath);
    return result;
  }
}
