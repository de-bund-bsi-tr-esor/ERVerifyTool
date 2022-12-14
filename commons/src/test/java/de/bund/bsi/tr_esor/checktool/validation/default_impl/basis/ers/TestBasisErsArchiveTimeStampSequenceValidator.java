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
package de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.is;

import java.util.Collections;
import java.util.function.Function;

import org.junit.BeforeClass;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampChain;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampSequence;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.report.ATSSequenceReport;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Unit test for {@link BasisErsArchiveTimeStampSequenceValidator}.
 *
 * @author HMA
 */
public class TestBasisErsArchiveTimeStampSequenceValidator
{

  private FormatOkReport ersFormatOk;

  /**
   * Loads test configuration.
   *
   * @throws Exception
   */
  @BeforeClass
  public static void setUpClass() throws Exception
  {
    TestUtils.loadDefaultConfig();
  }

  /**
   * Asserts that {@link BasisErsArchiveTimeStampSequenceValidator} invalidates formatOk if
   * {@link ArchiveTimeStampSequence} has no {@link ArchiveTimeStampChain}.
   *
   * @throws Exception
   */
  @Test
  public void noArchiveTimeStampChains() throws Exception
  {
    validate(er -> new ArchiveTimeStampSequence());
    assertThat("major", ersFormatOk.getOverallResult().getResultMajor(), endsWith(":invalid"));
    assertThat("summarized message",
               ersFormatOk.getSummarizedMessage(),
               containsString("must contain at least one ArchiveTimeStampChain"));
  }

  /**
   * Asserts that {@link BasisErsArchiveTimeStampSequenceValidator} keeps formatOk in context valid if
   * {@link ArchiveTimeStampSequence} has some {@link ArchiveTimeStampChain}. The checked
   * ArchiveTimeStampSequence is indetermined, because no online time stamp check was done.
   *
   * @throws Exception
   */
  @Test
  public void someArchiveTimeStamps() throws Exception
  {
    var report = validate(er -> er.getAtss());
    assertThat("major", report.getOverallResult().getResultMajor(), endsWith(":indetermined"));
    assertThat("summarized message",
               report.getSummarizedMessage(),
               is("0: no protected data to check\n0/0/tsp: no online validation of time stamp done"));
    report.getFormatted()
          .getArchiveTimeStampChain()
          .stream()
          .flatMap(atsc -> atsc.getArchiveTimeStamp().stream())
          .forEach(ats -> assertThat(ats.getFormatOK().getResultMajor(), endsWith(":valid")));
  }

  private ATSSequenceReport validate(Function<EvidenceRecord, ArchiveTimeStampSequence> getSequenceFor)
    throws Exception
  {
    var er = new ASN1EvidenceRecordParser().parse(TestUtils.decodeTestResource("/bin/basis_ers.b64"));
    var validator = new BasisErsArchiveTimeStampSequenceValidator();
    var ref = new Reference("er");
    var ctx = new ErValidationContext(ref, er, ProfileNames.BASIS_ERS,
                                      TestUtils.createReturnVerificationReport(), false);
    ctx.setDeclaredDigestOIDs(Collections.singletonList("2.16.840.1.101.3.4.2.1"));
    validator.setContext(ctx);
    var report = validator.validate(ref.newChild("test"), getSequenceFor.apply(er));
    ersFormatOk = ctx.getFormatOk();
    return report;
  }

}
