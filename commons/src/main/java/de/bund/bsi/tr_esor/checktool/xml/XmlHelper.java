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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.transform.Source;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import de.bund.bsi.tr_esor.xaip.XAIPType;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Helper class for handling XML requests and responses. Note that due to the many "xs:any"- elements in the schemas JAXB parsing will not
 * create the needed objects in a single run.
 *
 * @author TT
 */
public final class XmlHelper
{

    /**
     * Object factory for name space of details. Name space URI is "http://www.bsi.bund.de/tr-esor/vr/1.3".
     */
    public static final de.bund.bsi.tr_esor.vr.ObjectFactory FACTORY_ESOR_VR = new de.bund.bsi.tr_esor.vr.ObjectFactory();

    /**
     * Object factory for name space XAIP. Name space URI is "http://www.bsi.bund.de/tr-esor/xaip".
     */
    public static final de.bund.bsi.tr_esor.xaip.ObjectFactory FACTORY_XAIP = new de.bund.bsi.tr_esor.xaip.ObjectFactory();

    /**
     * Object factory for DSS elements. Name space URI is "urn:oasis:names:tc:dss:1.0:core:schema".
     */
    public static final oasis.names.tc.dss._1_0.core.schema.ObjectFactory FACTORY_DSS =
        new oasis.names.tc.dss._1_0.core.schema.ObjectFactory();

    /**
     * Object factory for XML signature elements. Name space URI is "http://www.w3.org/2000/09/xmldsig#".
     */
    public static final org.w3._2000._09.xmldsig_.ObjectFactory FACTORY_DSIG = new org.w3._2000._09.xmldsig_.ObjectFactory();

    /**
     * Object factory for name space of whole verification report. Name space URI is
     * "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#".
     */
    public static final oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ObjectFactory FACTORY_OASIS_VR =
        new oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ObjectFactory();

    /**
     * Object factory for name space used by OCSP identifiers, Name space URI is "http://uri.etsi.org/01903/v1.3.2#".
     */
    public static final org.etsi.uri._01903.v1_3.ObjectFactory FACTORY_ETSI = new org.etsi.uri._01903.v1_3.ObjectFactory();

    /**
     * Object factory for ETSI Signature Verification Report
     */
    public static final org.etsi.uri._19102.v1_2.ObjectFactory FACTORY_ETSI_SVR = new org.etsi.uri._19102.v1_2.ObjectFactory();

    /**
     * Object factory for name space ECARD. Name space URI is ""http://www.bsi.bund.de/ecard/api/1.1"".
     */
    public static final de.bund.bsi.ecard.api._1.ObjectFactory FACTORY_ECARD = new de.bund.bsi.ecard.api._1.ObjectFactory();

    public static final de.governikus.ecard.ext.ObjectFactory FACTORY_ECARD_EXT = new de.governikus.ecard.ext.ObjectFactory();

    /**
     * Object factory for name for ASIC.
     */
    public static final org.etsi.uri._02918.v1_2.ObjectFactory FACTORY_ASIC = new org.etsi.uri._02918.v1_2.ObjectFactory();

    private static final Map<String, JAXBContext> CACHE = new HashMap<>();

    private XmlHelper()
    {
        // no instances needed
    }

    /**
     * Returns a XAIP object parsed from input.
     *
     * @param data must contain a valid XAIP 1.2
     * @throws JAXBException
     */
    public static XAIPType parseXaip(InputStream data) throws JAXBException
    {
        return parse(new StreamSource(data),
            XAIPType.class,
            FACTORY_XAIP.getClass().getPackage().getName() + ":" + FACTORY_ASIC.getClass().getPackage().getName());
    }

    /**
     * Returns a XAIP object parsed from input.
     *
     * @param data must contain a valid XAIP 1.2
     * @throws JAXBException
     */
    public static XAIPType parseXaip(Element data) throws JAXBException
    {
        return parse(new DOMSource(data),
            XAIPType.class,
            FACTORY_XAIP.getClass().getPackage().getName() + ":" + FACTORY_ASIC.getClass().getPackage().getName());
    }

    private static JAXBContext getContext(String path) throws JAXBException
    {
        var result = CACHE.get(path);
        if (result == null)
        {
            result = JAXBContext.newInstance(path);
            CACHE.put(path, result);
        }
        return result;
    }

    /**
     * Parses given XML source.
     *
     * @param data XML source to parse
     * @param clazz class name of the target JAXB class
     * @param contextPath JAXB context path (i.e. the package name(s) of the JAXB classes)
     * @throws JAXBException
     */
    public static <T> T parse(Source data, Class<T> clazz, String contextPath) throws JAXBException
    {
        var ctx = getContext(contextPath);
        var u = ctx.createUnmarshaller();
        return u.unmarshal(data, clazz).getValue();
    }

    /**
     * Converts a verification report into a DOM element which can be digested by the WS stack. Note that the web service declares lots of
     * xs:any elements and does not know about contained types.
     *
     * @param report
     * @throws JAXBException
     */
    public static Element toElement(VerificationReportType report) throws JAXBException
    {
        return toElement(report, FACTORY_OASIS_VR.getClass().getPackage().getName(), FACTORY_OASIS_VR::createVerificationReport);
    }

    /**
     * Converts a given object into a DOM element.
     */
    public static <T> Element toElement(T data, String contextPath, Function<T, JAXBElement<T>> wrap) throws JAXBException
    {
        var ctx = getContext(contextPath);
        var result = new DOMResult();
        ctx.createMarshaller().marshal(wrap == null ? data : wrap.apply(data), result);
        return ((Document)result.getNode()).getDocumentElement();
    }

    /**
     * Gets an XMLGregorianCalendar of given parameters.
     *
     * @param date
     */
    public static XMLGregorianCalendar getXMLGregorianCalendar(Date date)
    {
        Calendar calendar = new GregorianCalendar();
        calendar.setTime(date);
        return getXMLGregorianCalendar(calendar);
    }

    /**
     * Gets an XMLGregorianCalendar of given parameters.
     *
     * @param cal
     */
    private static XMLGregorianCalendar getXMLGregorianCalendar(Calendar cal)
    {
        try
        {
            return DatatypeFactory.newInstance().newXMLGregorianCalendar((GregorianCalendar)cal);
        }
        catch (DatatypeConfigurationException e)
        {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Serializes a verification report to XML and writes it to an {@link OutputStream}.
     *
     * @param report
     * @param outs
     * @throws JAXBException
     */
    public static void serialize(VerificationReportType report, OutputStream outs) throws JAXBException
    {
        var ctx = getContext(FACTORY_OASIS_VR.getClass().getPackage().getName() + ":" + FACTORY_ESOR_VR.getClass().getPackage().getName());
        ctx.createMarshaller().marshal(FACTORY_OASIS_VR.createVerificationReport(report), outs);
    }

    /**
     * Canonicalize a XML node into a byte array using the given canonicalizer
     */
    public static byte[] canonicalizeSubtree(Canonicalizer canonicalizer, Node node) throws IOException, CanonicalizationException
    {
        try (var out = new ByteArrayOutputStream())
        {
            canonicalizer.canonicalizeSubtree(node, out);
            return out.toByteArray();
        }
    }
}
