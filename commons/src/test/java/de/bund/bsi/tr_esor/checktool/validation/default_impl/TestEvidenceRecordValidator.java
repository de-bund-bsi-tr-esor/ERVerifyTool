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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;

import org.junit.BeforeClass;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.entry.FileParameterFinder;
import de.bund.bsi.tr_esor.checktool.entry.ParameterFinder;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.EvidenceRecordReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;


/**
 * Tests the validation capabilities for evidence records.
 *
 * @author MO, ETR
 */
public class TestEvidenceRecordValidator
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
   * Tests three valid evidence records to be checked as valid. No assertions regarding the protected elements
   * are made. Result can be at most INDETERMINED because no only check of the time stamps is done. Note that
   * the context is not filled with protected documents, so presence of document hashes is not checked here.
   *
   * @throws Exception
   */
  @Test
  public void testValidER() throws Exception
  {
    String[] erToTest = {"/bin/example.ers.b64", "/xaip/xaip_ok.ers.b64", "/xaip/xaip_ok_sig_ok.ers.b64"};

    for ( String erName : erToTest )
    {
      byte[] erBytes = TestUtils.decodeTestResource(erName);
      EvidenceRecord er = new ASN1EvidenceRecordParser().parse(erBytes);
      EvidenceRecordValidator validator = new EvidenceRecordValidator();
      validator.setContext(new ErValidationContext(new Reference("dummy"), er, ProfileNames.RFC4998,
                                                   TestUtils.createReturnVerificationReport()));
      EvidenceRecordReport report = validator.validate(new Reference("dummy"), er);
      assertThat("validation result for " + erName,
                 report.getOverallResult().getResultMajor(),
                 is(ValidationResultMajor.INDETERMINED.toString()));
      assertTrue("result message contains no other messages than \"no online validation\" for every time stamp",
                 report.getSummarizedMessage()
                       .matches("atss/0: no protected data to check\\s(\\s?atss/0/\\d/tsp: no online validation of time stamp done\\s?)+"));
    }
  }

  /**
   * Tests that a valid additional redundant hash can lead to a positive verification result. The additional
   * hash has been calculated from the first partial hash tree and manually inserted into the second partial
   * hash tree which therefore should contain two hashes.
   *
   * @throws Exception
   */
  @Test
  public void testIntermediateHashInEr() throws Exception
  {
    EvidenceRecordReport report = getErReportForXaip("src/test/resources/xaip/xaip_ok_ers_intermediate_hash.xml");
    assertSecondHashInSecondHashTree(report);
    assertThat("A XAIP containing a valid intermediate hash gets a positive validation result.",
               report.getOverallResult().getResultMajor(),
               is(ValidationResultMajor.INDETERMINED.toString()));
    assertThat("The format of the ER containg an intermediate hash is validated as valid.",
               report.getFormatted().getFormatOK().getResultMajor(),
               is(ValidationResultMajor.VALID.toString()));
  }

  /**
   * Tests that a wrong additional hash leads to a negative verification result. The additional hash has been
   * manually inserted into the second partial hash tree which therefore should contain two hashes.
   *
   * @throws Exception
   */
  @Test
  public void testInvalidIntermediateHashInEr() throws Exception
  {
    EvidenceRecordReport report = getErReportForXaip("src/test/resources/xaip/xaip_nok_ers_wrong_intermediate_hash.xml");
    assertSecondHashInSecondHashTree(report);
    assertThat("A XAIP containg a wrong additional hash in the hash tree is invalid.",
               report.getOverallResult().getResultMajor(),
               is(ValidationResultMajor.INVALID.toString()));
    assertThat("The wrong additional hash leads to a hashValueMismatch result.",
               report.getOverallResult().getResultMinor(),
               is("http://www.bsi.bund.de/tr-esor/api/1.2/resultminor/hashValueMismatch"));
  }

  /**
   * Tests that missing document digests are recognized by the EvidenceRecordValidator.
   *
   * @throws Exception
   */
  @Test
  public void testMissingDigestInER() throws Exception
  {
    byte[] erBytes = TestUtils.decodeTestResource("/bin/example.ers.b64");
    EvidenceRecord er = new ASN1EvidenceRecordParser().parse(erBytes);
    EvidenceRecordValidator validator = new EvidenceRecordValidator();
    ErValidationContext ctx = new ErValidationContext(new Reference("dummy"), er, ProfileNames.RFC4998,
                                                      TestUtils.createReturnVerificationReport());
    ctx.addProtectedData(new Reference("notInER"),
                         "this is not protected by ER".getBytes(StandardCharsets.UTF_8));
    validator.setContext(ctx);
    EvidenceRecordReport report = validator.validate(new Reference("dummy"), er);
    assertThat("validation result with missing digests",
               report.getOverallResult().getResultMajor(),
               is(ValidationResultMajor.INVALID.toString()));
    assertThat("result message contains information about missing digest",
               report.getSummarizedMessage(),
               containsString("Missing digest(s) for: [notInER]"));
  }

  /**
   * Tests that wrong hash values in the hash tree lead to invalid result.
   *
   * @throws Exception
   */
  @Test
  public void testBrokenHashTree() throws Exception
  {
    byte[] erBytes = TestUtils.decodeTestResource("/xaip/xaip_nok.ers.b64");
    EvidenceRecord er = new ASN1EvidenceRecordParser().parse(erBytes);
    EvidenceRecordValidator validator = new EvidenceRecordValidator();
    validator.setContext(new ErValidationContext(new Reference("dummy"), er, ProfileNames.RFC4998,
                                                 TestUtils.createReturnVerificationReport()));
    EvidenceRecordReport report = validator.validate(new Reference("dummy"), er);
    assertThat("validation result with missing digests",
               report.getOverallResult().getResultMajor(),
               is(ValidationResultMajor.INVALID.toString()));
    assertThat("result message contains information about invalid hash tree root",
               report.getSummarizedMessage(),
               containsString("atss/0/0/hashTree: hash tree root hash does not match timestamp"));
  }

  /**
   * Asserts that a broken configuration or implementation (delegation not possible) leads to correct report.
   * We simulate that by executing a faked callValidator() line.
   */
  @Test
  public void delegationFailure() throws Exception
  {
    EvidenceRecordValidator validator = new EvidenceRecordValidator();
    Reference ref = new Reference("fake");
    validator.setContext(new ErValidationContext(ref, (EvidenceRecord)null, ProfileNames.RFC4998, null));
    TimeStampReport report = validator.callValidator("unsuported Object", ref, TimeStampReport.class);
    assertThat(report.getSummarizedMessage(), containsString("no validator found for java.lang.String"));
  }

  private EvidenceRecordReport getErReportForXaip(String testXaipPath) throws Exception
  {
    ParameterFinder params = new FileParameterFinder(Paths.get(testXaipPath), null, ProfileNames.RFC4998);
    EvidenceRecord er = new ASN1EvidenceRecordParser().parse(params.getXaip()
                                                                   .getCredentialsSection()
                                                                   .getCredential()
                                                                   .get(0)
                                                                   .getEvidenceRecord()
                                                                   .getAsn1EvidenceRecord());
    EvidenceRecordValidator validator = new EvidenceRecordValidator();
    validator.setContext(new ErValidationContext(new Reference("dummy"), er, ProfileNames.RFC4998,
                                                 TestUtils.createReturnVerificationReport()));
    return validator.validate(new Reference("dummy"), er);
  }

  private void assertSecondHashInSecondHashTree(EvidenceRecordReport report)
  {
    assertThat("An additional hash in the second partial hash tree is present.",
               report.getFormatted()
                     .getArchiveTimeStampSequence()
                     .getArchiveTimeStampChain()
                     .get(0)
                     .getArchiveTimeStamp()
                     .get(0)
                     .getReducedHashTree()
                     .getPartialHashTree()
                     .get(1)
                     .getHashValue(),
               hasSize(2));
  }
}
