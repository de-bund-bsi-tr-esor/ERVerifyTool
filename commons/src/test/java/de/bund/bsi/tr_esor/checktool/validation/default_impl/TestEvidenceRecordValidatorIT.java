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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.BeforeClass;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.EvidenceRecordReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Tests the validation capabilities for evidence records with available online validation.
 *
 * @author MO
 */
public class TestEvidenceRecordValidatorIT
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
   * Tests two valid evidence records to be checked as valid. No assertions regarding the protected elements
   * are made. Note that the context is not filled with protected documents, so presence of document hashes is
   * not checked here.
   *
   * @throws Exception
   */
  @Test
  public void testValidER() throws Exception
  {
    String[] erToTest = {"/xaip/xaip_ok.ers.b64", "/xaip/xaip_ok_sig_ok.ers.b64"};
    for ( String erName : erToTest )
    {
      byte[] erBytes = TestUtils.decodeTestResource(erName);
      EvidenceRecord er = new ASN1EvidenceRecordParser().parse(erBytes);
      EvidenceRecordValidator validator = new EvidenceRecordValidator();
      validator.setContext(new ErValidationContext(new Reference("dummy"), er, "online_profile", null));
      EvidenceRecordReport report = validator.validate(new Reference("dummy"), er);
      assertThat("validation result for " + erName,
                 report.getOverallResult().getResultMajor(),
                 is(ValidationResultMajor.INDETERMINED.toString()));
    }
  }

}
