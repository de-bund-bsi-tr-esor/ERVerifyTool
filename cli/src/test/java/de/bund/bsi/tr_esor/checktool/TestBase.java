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

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * Base class for testing the command line interface. Contains helper methods and assertions.
 *
 * @author TT
 */
public class TestBase
{

  /**
   * File path to the test resources directory. Access was OK so far, create temp files if commons sub-project
   * is not present.
   */
  protected static final String RES_DIR = "../commons/src/test/resources/";

  /**
   * Calls the command line interface and returns output.
   *
   * @param args
   * @return output from application
   * @throws IOException
   */
  protected static String callMain(String... args) throws IOException
  {
    try (ByteArrayOutputStream out = new ByteArrayOutputStream();
      PrintStream pout = new PrintStream(out, true, "UTF-8"))
    {
      Main.out = pout;
      Main.err = pout;
      Main.main(args);
      return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }
  }

  /**
   * Fails test if first major code in report is not as expected.
   *
   * @param report
   * @param expectedCode
   */
  protected void assertFirstMajor(String report, String expectedCode)
  {
    Pattern p = Pattern.compile("<([a-zA-Z]\\w*:)?ResultMajor( [^>]*)?>([^>]*)<");
    Matcher m = p.matcher(report);
    assertTrue(m.find());
    assertThat("first major code", m.group(3), containsString(expectedCode));
  }

  /**
   * Just makes sure that a certain element occurs n times in the report.
   *
   * @param report
   * @param name name of element
   * @param expected number of element of that name
   */
  protected void assertNumberElements(String report, String name, int expected)
  {
    Pattern p = Pattern.compile("<([a-zA-Z]\\w*:)?" + name + "( [^>]*)?>(.+?)</([a-zA-Z]\\w*:)?" + name + ">",
                                Pattern.DOTALL);
    Matcher m = p.matcher(report);
    for ( int i = 0 ; i < expected ; i++ )
    {
      assertTrue(i + "th occurrence of tag " + name, m.find());
    }
    assertFalse("too many occurrences of tag " + name, m.find());
  }

  /**
   * Provides a temporary file with test data.
   *
   * @param path resource with base64 encoded data
   * @throws IOException
   */
  protected File createDecodedTempFile(String path) throws IOException
  {
    File result = File.createTempFile("testOutput", ".bin");
    result.deleteOnExit();
    try (OutputStream outs = new FileOutputStream(result))
    {
      outs.write(TestUtils.decodeTestResource(path));
    }
    return result;
  }
}
