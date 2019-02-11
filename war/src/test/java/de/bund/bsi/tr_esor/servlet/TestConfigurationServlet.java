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
package de.bund.bsi.tr_esor.servlet;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;


/**
 * Unit test for {@link ConfigurationServlet}.
 *
 * @author HMA
 */
public class TestConfigurationServlet
{

  private File validConfigFile;

  private File invalidConfigFile;

  /**
   * Creates temporary files for test.
   *
   * @throws IOException
   */
  @Before
  public void setUp() throws IOException
  {
    validConfigFile = fromResource("/validConfig.xml");
    invalidConfigFile = fromResource("/invalidConfig.xml");
  }

  /**
   * Deletes temporary test files.
   */
  @After
  public void tearDown()
  {
    boolean ok = validConfigFile.delete();
    ok = invalidConfigFile.delete() && ok;
    assertTrue("deleted temp files", ok);
  }

  /**
   * Asserts that meaningful responses are written for various configuration files:
   * <ol>
   * <li>valid configuration file
   * <li>missing configuration file
   * <li>invalid configuration file
   * </ol>
   *
   * @throws Exception
   */
  @Test
  public void responseForVariousConfigurations() throws Exception
  {
    testConfiguration("valid config",
                      validConfigFile,
                      "<p><label>Default Profile</label>  <span>https://tools.ietf.org/html/rfc4998</span></p>");
    testConfiguration("missing config",
                      new File("mich_gibt_es_nicht.xml"),
                      "The configuration was not loaded.");
    testConfiguration("invalid config", invalidConfigFile, "The configuration was not loaded.");
  }

  /**
   * Assert if we use the configuration from class path primarily.
   */
  @Test
  public void useConfigFromClasspath() throws IOException
  {
    FakedConfigConfiguration systemUnderTest = new FakedConfigConfiguration();
    FakedConfigConfiguration.setConfigFile(invalidConfigFile);

    makeRequestAndAssert("config from classpath",
                         "<p><label>Default Profile</label>  <span>https://tools.ietf.org/html/rfc4998</span></p>",
                         systemUnderTest);

  }

  private void testConfiguration(String label, File configFile, String expectedContent) throws Exception
  {
    ConfigurationServlet systemUnderTest = new ConfigurationServlet();
    ConfigurationServlet.configFile = configFile;
    makeRequestAndAssert(label, expectedContent, systemUnderTest);
  }

  void makeRequestAndAssert(String label, String expectedContent, ConfigurationServlet systemUnderTest)
    throws IOException
  {
    HttpServletRequest req = mock(HttpServletRequest.class);
    when(req.getServletPath()).thenReturn("/loadConfiguration");
    HttpServletResponse resp = mock(HttpServletResponse.class);
    try (StringWriter sw = new StringWriter(); PrintWriter pw = new PrintWriter(sw))
    {
      when(resp.getWriter()).thenReturn(pw);
      systemUnderTest.doGet(req, resp);
      String html = sw.toString();
      assertThat(label, html, containsString(expectedContent));
    }
  }

  private File fromResource(String resource) throws IOException
  {
    File file = File.createTempFile(getClass().getSimpleName() + "_config", ".xml");
    try (InputStream is = getClass().getResourceAsStream(resource);
      OutputStream os = new FileOutputStream(file))
    {
      byte[] buf = new byte[1024];
      int len = is.read(buf);
      while (len > 0)
      {
        os.write(buf, 0, len);
        len = is.read(buf);
      }
    }
    return file;
  }

  /**
   * ConfigurationServlet with overwritten method for test to force usage of class path configuration.
   */
  static class FakedConfigConfiguration extends ConfigurationServlet
  {

    private static final long serialVersionUID = 1L;

    static void setConfigFile(File file)
    {
      configFile = file;
    }

    @Override
    InputStream getConfigFromClasspath()
    {
      return getClass().getResourceAsStream("/validConfig.xml");
    }
  }

}
