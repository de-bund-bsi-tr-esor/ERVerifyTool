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
package de.bund.bsi.tr_esor.checktool;

import java.io.IOException;

import org.junit.Test;


/**
 * Integration test for the main class only.
 *
 * @author MO
 */
public class TestMainIT extends TestBase
{

  /**
   * Asserts that a XAIP with embedded evidence records can be successfully validated with online service.
   *
   * @throws IOException
   */
  @Test
  public void testOnlineVerification() throws IOException
  {
    String report = callMain("-conf",
                             RES_DIR + "config.xml",
                             "-profile",
                             "online_profile",
                             "-data",
                             RES_DIR + "xaip/xaip_ok_sig_ers_2version.xml");
    assertFirstMajor(report, "valid");
  }

}
