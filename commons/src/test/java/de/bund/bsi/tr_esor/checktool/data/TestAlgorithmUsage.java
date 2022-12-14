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
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.sameInstance;

import java.util.Date;

import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage.UsageType;


/**
 * Unit test for {@link AlgorithmUsage}.
 *
 * @author HMA
 */
public class TestAlgorithmUsage
{

  /**
   * Asserts that creation works for hashed and signed usage type. Asserts that instances are immutable.
   */
  @Test
  public void creation() throws Exception
  {
    var date = new Date();
    var hashed = AlgorithmUsage.createHashed("1.2.3.4.5", date);
    assertThat(hashed.getUsage(), is(UsageType.DATA_HASHING));
    assertThat(hashed.getValidationDate(), allOf(is(date), not(sameInstance(date))));

    var signed = AlgorithmUsage.createSigned("1.2.3.4.5", date);
    assertThat(signed.getUsage(), is(UsageType.QES));
    assertThat(signed.getValidationDate(), allOf(is(date), not(sameInstance(date))));
  }

}
