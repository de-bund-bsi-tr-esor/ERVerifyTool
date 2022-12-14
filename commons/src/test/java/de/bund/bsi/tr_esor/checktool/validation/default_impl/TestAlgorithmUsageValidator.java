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
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.util.Date;

import org.hamcrest.Matcher;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Unit test for {@link AlgorithmUsageValidator}.
 *
 * @author BVO, HMA
 */
public class TestAlgorithmUsageValidator
{

  /**
   * Tests SHA256 which is valid.
   */
  @Test
  public void testValid()
  {
    checkAlgorithm(createValidatorUnderTest(), "2.16.840.1.101.3.4.2.1", ValidationResultMajor.VALID, null);
  }

  /**
   * Tests unknown OID which is unsupported.
   */
  @Test
  public void testUnsupported()
  {
    checkAlgorithm(createValidatorUnderTest(),
                   "1.12.0.99.2.9",
                   ValidationResultMajor.INVALID,
                   "/algorithm#hashAlgorithmNotSupported");
  }

  /**
   * Tests old OID which is not suitable.
   */
  @Test
  public void testNotSuitable()
  {
    checkAlgorithm(createValidatorUnderTest(),
                   "1.2.410.200004.1",
                   ValidationResultMajor.INVALID,
                   "/algorithm#hashAlgorithmNotSuitable");
  }

  /**
   * Asserts that a validation of the algorithm specified by given OID reports a result with given major code
   * and minor code ending.
   *
   * @param validator
   * @param oid
   * @param major
   * @param minorEnding
   */
  protected void checkAlgorithm(AlgorithmUsageValidator validator,
                                String oid,
                                ValidationResultMajor major,
                                String minorEnding)
  {
    Matcher<? super String> minorMatcher = minorEnding == null ? nullValue() : endsWith(minorEnding);
    var toCheck = AlgorithmUsage.createHashed(oid, new Date());
    var report = validator.validate(new Reference("foo"), toCheck);
    assertThat(report.getOverallResult().getResultMajor(), is(major.toString()));
    assertThat(report.getOverallResult().getResultMinor(), minorMatcher);
    assertThat(report.getFormatted().getSuitability().getResultMajor(), is(major.toString()));
    assertThat(report.getFormatted().getSuitability().getResultMinor(), minorMatcher);
  }

  /**
   * Returns new instance of validator to be tested.
   */
  protected AlgorithmUsageValidator createValidatorUnderTest()
  {
    return new AlgorithmUsageValidator();
  }

}
