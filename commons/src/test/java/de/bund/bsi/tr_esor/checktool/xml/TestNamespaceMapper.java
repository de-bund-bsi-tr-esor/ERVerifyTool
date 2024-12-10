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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;

import java.io.StringWriter;
import java.io.Writer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;


/**
 * Tests the name space prefix mapping for XAIP XML elements.
 *
 * @author MO
 */
public class TestNamespaceMapper
{

    /**
     * Tests the mapping with default configuration results in prefixes defined in the ESOR XAIP schema.
     *
     * @throws Exception
     */
    @Test
    public void testDefaultMapping() throws Exception
    {
        var doc = getDocument();
        var xaip = buildElementsWithWrongPrefix(doc);
        doc.appendChild(xaip);

        assertThat("Marshalled xml of unmapped element",
            toString(doc),
            allOf(containsString("<test1 xmlns"), containsString("<notStandardPrefix:test3 xmlns:notStandardPrefix")));
        var m = new NamespaceMapper(Collections.emptyMap());
        m.setNSPrefixRecursively(xaip);
        assertThat("Marshalled xml of unmapped element",
            toString(doc),
            allOf(containsString("<xaip:test1 xmlns:xaip="), containsString("<xades:test3 xmlns:xades=")));
    }

    /**
     * Tests the mapping with default configuration results in prefixes defined in the ESOR XAIP schema.
     *
     * @throws Exception
     */
    @Test
    public void testCustomMapping() throws Exception
    {
        var doc = getDocument();
        var xaip = buildElementsWithWrongPrefix(doc);
        doc.appendChild(xaip);
        Map<String, String> configuredPrefix = new HashMap<>();
        configuredPrefix.put("http://uri.etsi.org/01903/v1.3.2#", ""); // target namespace
        configuredPrefix.put("http://www.bsi.bund.de/tr-esor/xaip", "other");
        var m = new NamespaceMapper(configuredPrefix);
        m.setNSPrefixRecursively(xaip);
        assertThat("Marshalled xml of unmapped element",
            toString(doc),
            allOf(containsString("<other:test1 xmlns:other="), containsString("<test3 xmlns=")));
    }

    /**
     * Tests the mapping with default configuration results in prefixes defined in the ESOR XAIP schema.
     *
     * @throws Exception
     */
    @SuppressWarnings("unused")
    @Test
    public void testInvalidConfiguration() throws Exception
    {
        Map<String, String> configuredPrefix = new HashMap<>();
        configuredPrefix.put("http://uri.etsi.org/01903/v1.3.2#", ""); // target namespace
        configuredPrefix.put("http://www.bsi.bund.de/tr-esor/xaip/1.2", ""); // duplicate target namespace
        Assertions.assertThatExceptionOfType(IllegalArgumentException.class)
            .isThrownBy(() -> new NamespaceMapper(configuredPrefix))
            .withMessageContaining("Only one targetNamespace");
    }

    private Element buildElementsWithWrongPrefix(Document doc)
    {
        var xaip = doc.createElementNS("http://www.bsi.bund.de/tr-esor/xaip", "test1");
        var xaip2 = doc.createElementNS("http://www.bsi.bund.de/tr-esor/xaip", "test2");
        var xades = doc.createElementNS("http://uri.etsi.org/01903/v1.3.2#", "test3");
        xades.setPrefix("notStandardPrefix");
        xaip.appendChild(xaip2);
        xaip.appendChild(xades);
        return xaip;
    }

    private Document getDocument() throws ParserConfigurationException
    {
        var dbf = DocumentBuilderFactory.newInstance();
        var builder = dbf.newDocumentBuilder();
        return builder.newDocument();
    }

    private String toString(Document doc) throws Exception
    {
        var tf = TransformerFactory.newInstance().newTransformer();
        Writer out = new StringWriter();
        tf.transform(new DOMSource(doc), new StreamResult(out));
        return out.toString();
    }
}
