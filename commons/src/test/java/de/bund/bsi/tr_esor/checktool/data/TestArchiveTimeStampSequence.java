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

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;


/**
 * Tests the ArchiveTimeStampSequence representation class.
 *
 * @author MO
 */
public class TestArchiveTimeStampSequence
{

    /**
     * Asserts that a ASN&#46;1 ATSS from an EvidenceRecord can be parsed, encoded again and the encoded bytes are found in the
     * EvidenceRecord (encoded data must be identical to original data).
     */
    @Test
    public void parseAndEncode() throws Exception
    {
        var erBytes = TestUtils.decodeTestResource("/bin/example.ers.b64");
        var er = new ASN1EvidenceRecordParser().parse(erBytes);
        var atss = er.getAtss().getEncoded();
        assertTrue("Encoded ATSS is found in EvidenceRecord", findInArray(erBytes, atss));
    }

    @SuppressWarnings("PMD.AssignmentInOperand")
    private boolean findInArray(byte[] haystack, byte[] needle)
    {
        if (needle.length == 0)
        {
            return true;
        }
        var pos = 0;
        for (var i = 0; i < haystack.length; i++)
        {
            if (haystack[i] != needle[pos++])
            {
                pos = 0;
            }
            if (pos == needle.length)
            {
                return true;
            }
        }
        return false;
    }
}
