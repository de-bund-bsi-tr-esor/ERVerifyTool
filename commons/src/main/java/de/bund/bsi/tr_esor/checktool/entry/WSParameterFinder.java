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

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ASIC;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ECARD_EXT;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ESOR_VR;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ETSI;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ETSI_SVR;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_XAIP;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;

import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;

import org.bouncycastle.cms.CMSSignedData;
import org.w3._2000._09.xmldsig_.CanonicalizationMethodType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.parser.XaipParser;
import de.bund.bsi.tr_esor.checktool.validation.ParserFactory;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.ComprehensiveXaipSerializer;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.xaip.EvidenceRecordType;
import de.bund.bsi.tr_esor.xaip.XAIPType;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
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
     * @param request object as parsed by the web service, i.e. contents of xs:any elements are still generic elements
     */
    public WSParameterFinder(VerifyRequest request) throws JAXBException
    {
        super();
        handleProfileName(request.getProfile());
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
        var contextPath = XmlHelper.FACTORY_ESOR_VR.getClass().getPackage().getName();
        if (request.getOptionalInputs() != null)
        {
            for (var any : request.getOptionalInputs().getAny())
            {
                if (any instanceof ReturnVerificationReport)
                {
                    returnVerificationReport = (ReturnVerificationReport)any;
                }
                if (any instanceof Element)
                {
                    var element = (Element)any;
                    if (VR_NAMESPACE.equals(element.getNamespaceURI()) && "ReturnVerificationReport".equals(element.getLocalName()))
                    {
                        returnVerificationReport = XmlHelper.parse(new DOMSource(element), ReturnVerificationReport.class, contextPath);
                    }
                }
            }
        }
    }

    private void handleOther(AnyType other)
    {
        if (other != null)
        {
            for (var anyEr : other.getAny()) {
                var erXml = getErXML(anyEr);
                try {
                    var erParameter = new ERParameter();
                    erParameter.setEr(new ASN1EvidenceRecordParser().parse(erXml.getAsn1EvidenceRecord()));
                    erParameter.setErRef(new Reference(DETACHED_ER_ID));
                    erParameter.getErRef().setxPath("SignatureObject/Other/evidenceRecord/asn1EvidenceRecord");
                    erParameter.setXaipVersionAddressedByEr(erXml.getVersionID());
                    erParameter.setXaipAoidAddressedByEr(erXml.getAOID());
                    providedERs.add(erParameter);
                } catch (IOException e) {
                    throw new IllegalArgumentException("invalid content in element xaip:evidenceRecord", e);
                }
            }
            return;
        }
        throw new IllegalArgumentException("only Base64Signature or other/evidenceRecord/asn1EvidenceRecord are supported");
    }

    private EvidenceRecordType getErXML(Object element)
    {
        if (element instanceof Element)
        {
            var elem = (Element)element;
            if ("evidenceRecord".equals(elem.getLocalName()) && "http://www.bsi.bund.de/tr-esor/xaip".equals(elem.getNamespaceURI()))
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
        else if (element instanceof JAXBElement<?> && ((JAXBElement<?>)element).getValue() instanceof EvidenceRecordType)
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
            var parsed = ParserFactory.parse(ins, getProfileName());
            var xPath = "SignatureObject/Base64Signature/Value";
            if (parsed instanceof CMSSignedData)
            {
                cmsDocument = (CMSSignedData)parsed;
                cmsRef = new Reference("CmsSignature");
                cmsRef.setxPath(xPath);
            }
            else if (parsed instanceof XAIPType)
            {
                var xr = new Reference("XAIP");
                xr.setxPath(xPath);
                setXaipAttributes((XAIPType)parsed, xr);
            }
            else if (parsed instanceof EvidenceRecord)
            {
                var erParameter = new ERParameter();
                erParameter.setErRef(new Reference(DETACHED_ER_ID));
                erParameter.getErRef().setxPath(xPath);
                erParameter.setEr((EvidenceRecord)parsed);
                providedERs.add(erParameter);
            }
            else if (parsed instanceof EvidenceRecordType)
            {
                var erParameter = new ERParameter();
                erParameter.setErRef(new Reference(DETACHED_ER_ID));
                erParameter.getErRef().setxPath("/evidenceRecord/asn1EvidenceRecord");
                erParameter.setEr(new ASN1EvidenceRecordParser().parse(((EvidenceRecordType)parsed).getAsn1EvidenceRecord()));
                erParameter.setXaipVersionAddressedByEr(((EvidenceRecordType)parsed).getVersionID());
                providedERs.add(erParameter);
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
        var numberDoc = 0;
        for (var doc : request.getInputDocuments().getDocumentOrTransformedDataOrDocumentHash())
        {
            numberDoc++;
            if (!(doc instanceof DocumentType))
            {
                throw new IllegalArgumentException("only Documents supported as input");
            }
            var document = (DocumentType)doc;
            if (document.getInlineXML() != null) // NOPMD: searching for the one non-null element
            {
                setXaipAttributes(getXAIPXML(document.getInlineXML().getAny()),
                    createRefForDocument("XAIP", document.getID(), numberDoc, "/InlineXML"));
            }
            else if (document.getBase64XML() != null) // NOPMD: searching for the one non-null element
            {
                var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory(getProfileName()));
                var parser = new XaipParser(lXaipReader);
                parser.setInput(new ByteArrayInputStream(document.getBase64XML()));
                try
                {
                    var xas = parser.parse();
                    setXaipAttributes(xas.getXaip(), createRefForDocument("XAIP", document.getID(), numberDoc, "/Base64XML"));
                    serializer = xas.getSerializer();
                }
                catch (IOException e)
                {
                    throw new IllegalArgumentException("cannot parse Base64XML as XAIP");
                }
            }
            else if (document.getBase64Data() != null) // NOPMD: searching for the one non-null element
            {
                var ref = createRefForDocument("Bin" + numberDoc, document.getID(), numberDoc, "/Base64Data/Value");
                binaryDocuments.put(ref, document.getBase64Data().getValue());
            }
            else
            {
                throw new IllegalArgumentException("only Base64Data, Base64XML or InlineXML is supported in a Document");
            }
        }
    }

    private XAIPType getXAIPXML(Object element) throws JAXBException
    {
        var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory(getProfileName()));
        // Usually the inlineXML object is already correctly deserialized...
        if (element instanceof JAXBElement && ((JAXBElement<?>)element).getValue() instanceof XAIPType)
        {
            var document = marshal(element);
            var xaip = (XAIPType)((JAXBElement<?>)element).getValue();
            serializer = new ComprehensiveXaipSerializer(document, determineCanonicalizationAlgorithm(xaip), lXaipReader, true);
            return xaip;
        }
        // If not, deserialize it now. This happens only if the VerifyRequest is directly passed to
        // S4VerifyOnly.verify.
        if (element instanceof Element)
        {
            var elem = (Element)element;
            var xaip = XmlHelper.parseXaip(elem);
            serializer = new ComprehensiveXaipSerializer(((Element)element).getOwnerDocument(),
                determineCanonicalizationAlgorithm(xaip),
                lXaipReader,
                true);
            return xaip;
        }
        throw new IllegalArgumentException("InlineXML could not be parsed as XAIP");
    }

    private Document marshal(Object element) throws JAXBException
    {
        DOMResult res = new DOMResult();
        var packages = List.of(FACTORY_XAIP.getClass().getPackage().getName(),
            FACTORY_ESOR_VR.getClass().getPackage().getName(),
            FACTORY_ECARD_EXT.getClass().getPackage().getName(),
            FACTORY_ETSI_SVR.getClass().getPackage().getName(),
            FACTORY_ETSI.getClass().getPackage().getName(),
            FACTORY_ASIC.getClass().getPackage().getName());
        var contextPath = String.join(":", packages);
        var context = JAXBContext.newInstance(contextPath, getClass().getClassLoader());
        var marshaller = context.createMarshaller();
        marshaller.marshal(element, res);
        return (Document)res.getNode();
    }

    private static String determineCanonicalizationAlgorithm(XAIPType xaip)
    {
        return Optional.ofNullable(xaip.getPackageHeader().getCanonicalizationMethod())
            .map(CanonicalizationMethodType::getAlgorithm)
            .orElse("http://www.w3.org/2001/10/xml-exc-c14n#");
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
        var result = new Reference(name);
        var docPart = docId == null ? "Document[" + numberDoc + "]" : "Document[@id='" + docId + "']";
        result.setxPath("VerifyRequest/InputDocuments/" + docPart + subPath);
        return result;
    }
}
