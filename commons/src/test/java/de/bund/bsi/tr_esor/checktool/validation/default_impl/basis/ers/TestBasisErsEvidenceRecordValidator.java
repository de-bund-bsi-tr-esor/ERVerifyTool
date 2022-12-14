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
import static org.hamcrest.Matchers.*;

import java.util.ArrayList;
import java.util.Collections;

import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampChain;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampSequence;
import de.bund.bsi.tr_esor.checktool.data.CryptoInfo;
import de.bund.bsi.tr_esor.checktool.data.EncryptionInfo;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.EvidenceRecordValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.TestEvidenceRecordValidator;
import de.bund.bsi.tr_esor.checktool.validation.report.EvidenceRecordReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Unit test for {@link BasisErsEvidenceRecordValidator}.
 *
 * @author HMA
 */
public class TestBasisErsEvidenceRecordValidator extends TestEvidenceRecordValidator
{

  private final Reference reference = new Reference(this.getClass().getSimpleName());

  private final BasisErsEvidenceRecordValidator basisErsValidator = new BasisErsEvidenceRecordValidator();

  private final EvidenceRecordValidator rfc4998Validator = new EvidenceRecordValidator();

  /**
   * Loads the default configuration.
   *
   * @throws Exception
   */
  @BeforeClass
  public static void setUpClass() throws Exception
  {
    TestUtils.loadDefaultConfig();
  }

  protected EvidenceRecordValidator createValidator()
  {
    return new BasisErsEvidenceRecordValidator();
  }

  /**
   * Asserts that an evidence record which conforms to Basis-ERS-Profile is validated and reported as valid.
   *
   * @throws Exception
   */
  @Test
  public void validBasisErs() throws Exception
  {
    var er = createEvidenceRecord(1, null, null);

    assertThat("BASIS-ERS validation",
               validateAgainstBasisErs(er).getOverallResult().getResultMajor(),
               endsWith(":valid"));

    assertThat("RFC4998 validation",
               validateAgainstRfc4998(er).getOverallResult().getResultMajor(),
               endsWith(":valid"));
  }

  /**
   * Asserts that violations of Basis-ERS-Profile in a RFC4998 evidence record are detected and reported.
   *
   * @throws Exception
   */
  @Test
  public void invalidBasisErsButValidRfc4998() throws Exception
  {
    var er = createEvidenceRecord(1, Mockito.mock(CryptoInfo.class), Mockito.mock(EncryptionInfo.class));

    var report = validateAgainstBasisErs(er);
    assertThat("BASIS-ERS validation", report.getOverallResult().getResultMajor(), endsWith(":invalid"));
    var msg = report.getSummarizedMessage();
    assertThat(msg, containsString("cryptoInfo: must be omitted"));
    assertThat(msg, containsString("encryptionInfo: must be omitted"));

    assertThat("RFC4998 validation",
               validateAgainstRfc4998(er).getOverallResult().getResultMajor(),
               endsWith(":valid"));
  }

  /**
   * Asserts that violations of RFC4998 are also reported for Basis-ERS-Profile.
   *
   * @throws Exception
   */
  @Test
  public void invalidRfc4998() throws Exception
  {
    var er = createEvidenceRecord(0, Mockito.mock(CryptoInfo.class), Mockito.mock(EncryptionInfo.class));

    var report = validateAgainstBasisErs(er);
    assertThat("BASIS-ERS validation", report.getOverallResult().getResultMajor(), endsWith(":invalid"));

    assertThat("RFC4998 validation",
               validateAgainstRfc4998(er).getOverallResult().getResultMajor(),
               endsWith(":invalid"));
  }

  private EvidenceRecord createEvidenceRecord(int version, CryptoInfo ci, EncryptionInfo ei) throws Exception
  {
    var ats = Mockito.mock(ArchiveTimeStamp.class);
    var atsc = Mockito.mock(ArchiveTimeStampChain.class);
    Mockito.when(atsc.iterator()).thenReturn(Collections.singletonList(ats).iterator());
    var atss = Mockito.mock(ArchiveTimeStampSequence.class);
    Mockito.when(atss.iterator()).thenReturn(Collections.singletonList(atsc).iterator());
    return new EvidenceRecord(version, new ArrayList<>(), atss, ci, ei);
  }

  private EvidenceRecordReport validateAgainstBasisErs(EvidenceRecord er) throws ReflectiveOperationException
  {
    basisErsValidator.setContext(new ErValidationContext(reference, er, ProfileNames.BASIS_ERS,
                                                         TestUtils.createReturnVerificationReport(), true));
    var result = basisErsValidator.validate(reference, er);
    assertThat(result.getFormatted().getReportVersion(), is("1.3.0"));
    return result;
  }

  private EvidenceRecordReport validateAgainstRfc4998(EvidenceRecord er) throws ReflectiveOperationException
  {
    rfc4998Validator.setContext(new ErValidationContext(reference, er, ProfileNames.RFC4998,
                                                        TestUtils.createReturnVerificationReport(), true));
    return rfc4998Validator.validate(reference, er);
  }

}
