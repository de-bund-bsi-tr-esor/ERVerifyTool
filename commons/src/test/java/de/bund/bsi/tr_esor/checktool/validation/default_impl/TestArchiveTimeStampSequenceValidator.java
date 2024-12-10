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
package de.bund.bsi.tr_esor.checktool.validation.default_impl;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.BeforeClass;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;


/**
 * Tests the validation capabilities for ArchiveTimeStampSequences.
 *
 * @author MO
 */
public class TestArchiveTimeStampSequenceValidator
{

    /**
     * Loads default configuration.
     */
    @BeforeClass
    public static void setUpClass() throws Exception
    {
        TestUtils.loadDefaultConfig();
    }

    /**
     * Tests two valid evidence records to be checked as valid. No assertions regarding the protected elements are made. Result can be at
     * most INDETERMINED because no only check of the timestamps is done.
     *
     * @throws Exception
     */
    @Test
    public void testValidER() throws Exception
    {
        var erToTest = new String[]{"/xaip/xaip_ok.rehashed.ers.b64", "/bin/example.ers.b64"};
        for (var erName : erToTest)
        {
            var erBytes = TestUtils.decodeTestResource(erName);
            var er = new ASN1EvidenceRecordParser().parse(erBytes);
            var ctx = new ErValidationContext(new Reference("dummy"), er, ProfileNames.RFC4998, null, false);
            ctx.setDeclaredDigestOIDs(er.getDigestAlgorithms());
            var atssv = new ArchiveTimeStampSequenceValidator();
            atssv.setContext(ctx);
            ReportPart report = atssv.validate(new Reference("dummy"), er.getAtss());
            assertThat("ATSS validation result for " + erName,
                report.getOverallResult().getResultMajor(),
                is(ValidationResultMajor.INDETERMINED.toString()));
        }
    }

}
