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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

import org.hamcrest.Matcher;
import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.parser.XaipParser;
import de.bund.bsi.tr_esor.checktool.validation.VersionNotFoundException;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.xaip.CredentialType;
import de.bund.bsi.tr_esor.xaip.XAIPType;


/**
 * Test for the XAIP reader for physical XAIPs
 */
@SuppressWarnings({"PMD.CommentRequired", "checkstyle:JavadocMethod"})
public class TestXaipReader
{

    private static final Reference REFERENCE = new Reference("XAIP");

    private static final String PROFILE_NAME = ProfileNames.RFC4998;

    private XaipReader sut;

    /**
     * Creates new {@link XaipReader} for an example XAIP.
     */
    @Before
    public void initializeSystemUnderTest() throws Exception
    {
        TestUtils.loadDefaultConfig();
    }

    /**
     * Asserts that the EvidenceRecords can be obtained.
     */
    @Test
    public void testGetEvidenceRecords() throws Exception
    {
        sut = new XaipReader(xaip("/xaip/xaip_ok_ers.xml"), REFERENCE, PROFILE_NAME);

        var evidenceRecords =
            sut.getEvidenceRecords().values().stream().map(CredentialType::getEvidenceRecord).collect(Collectors.toList());
        assertThat(evidenceRecords, hasSize(1));
        assertThat(evidenceRecords.get(0).getAOID(), is("d9984bc6-2268-4d93-a9ea-50b20dfde3db"));
        assertThat(evidenceRecords.get(0).getVersionID(), is("V001"));
    }

    /**
     * Asserts exception with useful message in case of illegal version ID.
     */
    @Test
    public void testGetProtectedElementsByWrongVersionID() throws Exception
    {
        sut = new XaipReader(xaip("/xaip/xaip_ok_ers.xml"), REFERENCE, PROFILE_NAME);

        var actual = assertThrows(VersionNotFoundException.class, () -> sut.prepareProtectedElements("Nada", null));
        assertThat(actual.getMessage(), is("The requested version Nada could not be found in the XAIP. Available versions are: [V001]"));
    }

    @Test
    public void getsProtectedMetaDataObject() throws Exception
    {
        var parser = new XaipParser(null);
        try (var input = getClass().getResourceAsStream("/xaip/xaip_ok_ers.xml"))
        {
            assertThat(input, notNullValue());
            parser.setInput(input);
            var xaip = parser.parse().getXaip();
            sut = new XaipReader(xaip, REFERENCE, PROFILE_NAME);
        }

        var protectedElements = sut.prepareProtectedElements("V001", parser.createSerializer());

        checkElement(protectedElements, "metaDataID:Hundename_V001", containsString("TestData"));
    }

    @Test
    public void getsProtectedVersionManifestObject() throws Exception
    {
        var parser = new XaipParser(null);
        try (var input = getClass().getResourceAsStream("/xaip/xaip_ok_ers.xml"))
        {
            assertThat(input, notNullValue());
            parser.setInput(input);
            var xaip = parser.parse().getXaip();
            sut = new XaipReader(xaip, REFERENCE, PROFILE_NAME);
        }

        var protectedElements = sut.prepareProtectedElements("V001", parser.createSerializer());

        checkElement(protectedElements, "versionID:V001", startsWith("<xaip:versionManifest"));
    }

    @Test
    public void getsProtectedDataObjectFromXaip() throws Exception
    {
        var parser = new XaipParser(null);
        try (var input = getClass().getResourceAsStream("/xaip/xaip_ok_ers.xml"))
        {
            assertThat(input, notNullValue());
            parser.setInput(input);
            var xaip = parser.parse().getXaip();
            sut = new XaipReader(xaip, REFERENCE, PROFILE_NAME);
        }

        var protectedElements = sut.prepareProtectedElements("V001", parser.createSerializer());

        checkElement(protectedElements, "dataObjectID:HundesteuerAnmeldung_V001", startsWith("my name is"));
    }

    @Test
    public void getsProtectedDataObjectFromLXaip() throws Exception
    {
        var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory("TR-ESOR"));
        var parser = new XaipParser(lXaipReader);
        try (var input = getClass().getResourceAsStream("/lxaip/lxaip_ok.xml"))
        {
            assertThat(input, notNullValue());
            parser.setInput(input);
            var xaip = parser.parse().getXaip();
            sut = new XaipReader(xaip, REFERENCE, PROFILE_NAME);
        }

        var protectedElements = sut.prepareProtectedElements("V001", parser.createSerializer());

        checkElement(protectedElements,
            "dataObjectID:HundesteuerAnmeldung_V001",
            startsWith("Dies ist ein Testdokument mit qualifizierter Signatur"));
    }

    private void checkElement(Map<Reference, byte[]> protectedElements, String field, Matcher<String> expected)
    {
        assertThat("Content of " + field, new String(protectedElements.get(REFERENCE.newChild(field)), StandardCharsets.UTF_8), expected);
    }

    private static XAIPType xaip(String file) throws Exception
    {
        return XmlHelper.parseXaip(TestXaipReader.class.getResourceAsStream(file));
    }
}
