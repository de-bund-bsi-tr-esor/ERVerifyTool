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
package de.bund.bsi.tr_esor.checktool.conf;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;

import java.util.Calendar;
import java.util.Collections;
import java.util.Map;

import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.conf.AlgorithmCatalog.SupportedHashAlgorithm;


/**
 * Unit test for {@link AlgorithmCatalog}.
 *
 * @author HMA
 */
public class TestAlgorithmCatalog
{

  /**
   * Asserts that the supported algorithms can be returned.
   */
  @Test
  public void testGetSupportedAlgorithms() throws Exception
  {
    Map<String, SupportedHashAlgorithm> algorithms = AlgorithmCatalog.getInstance().getSupportedAlgorithms();

    SupportedHashAlgorithm sha256 = algorithms.get("SHA256");
    assertThat(sha256.getOids(), contains("1.2.840.113549.2.9", "2.16.840.1.101.3.4.2.1"));
    expiresAfter(sha256, 2023, 12, 31);
    assertThat(sha256.getParameter(), is(Collections.emptyMap()));

    SupportedHashAlgorithm dsa = algorithms.get("DSA");
    assertThat(dsa.getOids(), contains("1.2.840.10040.4"));
    expiresAfter(dsa, 2022, 12, 31);
    Map<String, String> params = dsa.getParameter();
    assertThat("params", params.entrySet(), hasSize(2));
    assertThat("plength", params.get("plength"), is("2048"));
    assertThat("qlength", params.get("qlength"), is("256"));
  }

  private void expiresAfter(SupportedHashAlgorithm sha256, int year, int month, int day)
  {
    Calendar cal = Calendar.getInstance();
    cal.setTime(sha256.getValidity());
    assertEquals("year", year, cal.get(Calendar.YEAR));
    assertEquals("month", month, cal.get(Calendar.MONTH) + 1);
    assertEquals("day", day, cal.get(Calendar.DATE));
  }

}
