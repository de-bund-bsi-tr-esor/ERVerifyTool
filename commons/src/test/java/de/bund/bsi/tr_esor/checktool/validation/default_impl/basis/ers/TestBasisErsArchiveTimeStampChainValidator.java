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
import static org.junit.Assert.fail;

import java.io.IOException;
import java.util.Collections;
import java.util.Date;
import java.util.function.Function;

import org.bouncycastle.asn1.DERSequence;
import org.junit.BeforeClass;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampChain;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.report.ATSChainReport;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Unit test for {@link BasisErsArchiveTimeStampChainValidator}.
 *
 * @author HMA
 */
public class TestBasisErsArchiveTimeStampChainValidator
{

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

  private FormatOkReport ersFormatOk;

  /**
   * Asserts that {@link BasisErsArchiveTimeStampChainValidator} invalidates formatOk if
   * {@link ArchiveTimeStampChain} has no {@link ArchiveTimeStamp}.
   *
   * @throws Exception
   */
  @Test
  public void noArchiveTimeStamps() throws Exception
  {
    validate(er -> emptyChain());
    assertThat("major", ersFormatOk.getOverallResult().getResultMajor(), endsWith(":invalid"));
    assertThat("summarized Message",
               ersFormatOk.getSummarizedMessage(),
               containsString("must contain at least one ArchiveTimeStamp"));
  }

  /**
   * Asserts that {@link BasisErsArchiveTimeStampChainValidator} keeps formatOk in context valid if
   * {@link ArchiveTimeStampChain} has some {@link ArchiveTimeStamp}. The checked ArchiveTimeStampChain is
   * indetermined, because no online time stamp check was done.
   *
   * @throws Exception
   */
  @Test
  public void someArchiveTimeStamps() throws Exception
  {
    ATSChainReport report = validate(er -> er.getAtss().get(0));
    assertThat("major", report.getOverallResult().getResultMajor(), endsWith(":indetermined"));
    assertThat("summarized Message",
               report.getSummarizedMessage(),
               is("no protected data to check\n0/tsp: no online validation of time stamp done"));
    report.getFormatted()
          .getArchiveTimeStamp()
          .forEach(ats -> assertThat(ats.getFormatOK().getResultMajor(), endsWith(":valid")));

  }

  private ATSChainReport validate(Function<EvidenceRecord, ArchiveTimeStampChain> getChainFor)
    throws Exception
  {
    EvidenceRecord er = new ASN1EvidenceRecordParser().parse(TestUtils.decodeTestResource("/bin/basis_ers.b64"));
    ArchiveTimeStampChain chain = getChainFor.apply(er);
    BasisErsArchiveTimeStampChainValidator validator = new BasisErsArchiveTimeStampChainValidator();
    Reference ref = new Reference("er");
    ErValidationContext ctx = new ErValidationContext(ref, er, ProfileNames.BASIS_ERS,
                                                      TestUtils.createReturnVerificationReport());
    if (!chain.isEmpty())
    {
      Date dateFromTimeStamp = new Date(chain.get(0).getSignDateFromTimeStamp().getTime());
      dateFromTimeStamp.setTime(dateFromTimeStamp.getTime() + 1);
      ctx.setSecureData(chain.get(0), dateFromTimeStamp);
    }
    ctx.setDeclaredDigestOIDs(Collections.singletonList("2.16.840.1.101.3.4.2.1"));
    validator.setContext(ctx);
    ATSChainReport report = validator.validate(ref.newChild("test"), chain);
    ersFormatOk = ctx.getFormatOk();
    return report;
  }

  private ArchiveTimeStampChain emptyChain()
  {
    try
    {
      return new ArchiveTimeStampChain(new DERSequence());
    }
    catch (IOException e)
    {
      fail("need empty ATS chain for this test" + e.getMessage());
      return null;
    }
  }

}
