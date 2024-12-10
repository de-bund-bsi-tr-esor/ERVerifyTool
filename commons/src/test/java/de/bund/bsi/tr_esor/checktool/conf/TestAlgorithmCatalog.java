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


import static org.assertj.core.api.Assertions.assertThat;

import java.util.Calendar;

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
        var algorithms = AlgorithmCatalog.getInstance().getSupportedAlgorithms();

        var sha256 = algorithms.get("SHA256");
        assertThat(sha256.getOids()).contains("1.2.840.113549.2.9", "2.16.840.1.101.3.4.2.1");
        expiresAfter(sha256, 2099, 12, 31);
        assertThat(sha256.getParameter()).isEmpty();

        var dsa = algorithms.get("DSA");
        assertThat(dsa.getOids()).contains("1.2.840.10040.4");
        expiresAfter(dsa, 2025, 12, 31);
        var params = dsa.getParameter();
        assertThat(params).hasSize(2);
        assertThat(params.get("plength")).isEqualTo("2048");
        assertThat(params.get("qlength")).isEqualTo("250");
    }

    private void expiresAfter(SupportedHashAlgorithm sha256, int year, int month, int day)
    {
        var cal = Calendar.getInstance();
        cal.setTime(sha256.getValidity());
        assertThat(year).isEqualTo(cal.get(Calendar.YEAR));
        assertThat(month).isEqualTo(cal.get(Calendar.MONTH) + 1);
        assertThat(day).isEqualTo(cal.get(Calendar.DATE));
    }
}
