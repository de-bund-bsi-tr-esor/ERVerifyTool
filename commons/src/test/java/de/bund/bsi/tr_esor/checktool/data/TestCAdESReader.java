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
package de.bund.bsi.tr_esor.checktool.data;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.bouncycastle.cms.CMSSignedData;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;


/**
 * Unit test for {@link CAdESReader}.
 *
 * @author HMA
 */
public class TestCAdESReader
{

    /**
     * Asserts CMS with embedded evidence record can be read.
     */
    @Test
    public void encapsulatedWithEr() throws Exception
    {
        var bytes = TestUtils.decodeTestResource("/cms/encapsulated_with_er.p7s.b64");
        var signature = new CMSSignedData(bytes);
        var reader = new CAdESReader(signature);
        assertFalse(reader.hasCertificateValues());
        assertFalse(reader.hasRevocationValues());
        assertTrue(reader.hasUnsignedAttributes());
        var erBytes = reader.getEmbeddedEvidenceRecord();
        assertThat(erBytes, notNullValue());
        assertThat(new ASN1EvidenceRecordParser().parse(erBytes), notNullValue());
    }

    /**
     * Asserts CMS without embedded evidence record can be read.
     */
    @Test
    public void detached() throws Exception
    {
        var bytes = TestUtils.decodeTestResource("/cms/TestDataLogo.png_er.p7s.b64");
        var signature = new CMSSignedData(bytes);
        var reader = new CAdESReader(signature);
        assertFalse(reader.hasCertificateValues());
        assertFalse(reader.hasRevocationValues());
        assertTrue(reader.hasUnsignedAttributes());
        assertThat(reader.getEmbeddedEvidenceRecord(), nullValue());
    }

}
