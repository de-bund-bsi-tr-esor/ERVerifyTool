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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


/**
 * Unit test for {@link ConfigurationServlet}.
 *
 * @author HMA
 */
public class TestConfigurationServlet
{

    private static Path VALID_CONFIG;

    private static Path INVALID_CONFIG;

    /**
     * Creates temporary files for test.
     */
    @BeforeClass
    public static void beforeClass() throws Exception
    {
        VALID_CONFIG = fromResource("/validConfig.xml").toPath();
        INVALID_CONFIG = fromResource("/invalidConfig.xml").toPath();
    }

    /**
     * Deletes temporary test files.
     */
    @AfterClass
    public static void afterClass() throws IOException
    {
        Files.delete(VALID_CONFIG);
        Files.delete(INVALID_CONFIG);
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
            VALID_CONFIG,
            "<p><label>Default Profile</label> <span>https://tools.ietf.org/html/rfc4998</span></p>");
        testConfiguration("missing config",
            Path.of("mich_gibt_es_nicht.xml"),
            "The configuration has been loaded from the application war file.");
        testConfiguration("invalid config", INVALID_CONFIG, "The configuration was not loaded.");
    }

    /**
     * Assert that we use the configuration from class path if no other is available.
     */
    @Test
    public void useConfigFromClasspath() throws IOException
    {
        var systemUnderTest = new FakedConfigConfiguration();
        FakedConfigConfiguration.setConfigFile(Path.of("inexistent"));

        makeRequestAndAssert("config from classpath",
            "<p><label>Default Profile</label> <span>https://tools.ietf.org/html/rfc4998</span></p>",
            systemUnderTest);

    }

    private void testConfiguration(String label, Path configFile, String expectedContent) throws Exception
    {
        var systemUnderTest = new FakedConfigConfiguration();
        ConfigurationServlet.configFile = configFile;
        makeRequestAndAssert(label, expectedContent, systemUnderTest);
    }

    void makeRequestAndAssert(String label, String expectedContent, ConfigurationServlet systemUnderTest) throws IOException
    {
        var req = mock(HttpServletRequest.class);
        when(req.getServletPath()).thenReturn("/loadConfiguration");
        var resp = mock(HttpServletResponse.class);
        try (var sw = new StringWriter();
            var pw = new PrintWriter(sw))
        {
            when(resp.getWriter()).thenReturn(pw);
            systemUnderTest.doGet(req, resp);
            var html = sw.toString();
            assertThat(label, html, containsString(expectedContent));
        }
    }

    private static File fromResource(String resource) throws IOException
    {
        var file = File.createTempFile(TestConfigurationServlet.class.getSimpleName() + "_config", ".xml");
        try (var is = TestConfigurationServlet.class.getResourceAsStream(resource);
            OutputStream os = new FileOutputStream(file))
        {
            is.transferTo(os);
        }
        return file;
    }

    /**
     * ConfigurationServlet with overwritten method for test to force usage of class path configuration.
     */
    static class FakedConfigConfiguration extends ConfigurationServlet
    {

        private static final long serialVersionUID = 1L;

        static void setConfigFile(Path path)
        {
            configFile = path;
        }

        @Override
        protected InputStream loadConfigFromClasspath()
        {
            return getClass().getResourceAsStream("/validConfig.xml");
        }
    }

}
