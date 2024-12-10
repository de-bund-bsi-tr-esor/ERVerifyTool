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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;


/**
 * Base class for testing the command line interface. Contains helper methods and assertions.
 *
 * @author TT
 */
public class TestBase extends FileOutputChecker
{

    /**
     * File path to the test resources directory. Access was OK so far, create temp files if commons sub-project is not present.
     */
    protected static final String RES_DIR = "../commons/src/test/resources/";

    /**
     * Calls the command line interface and returns output.
     *
     * @return output from application
     */
    protected static String callMain(String... args) throws IOException
    {
        try (var out = new ByteArrayOutputStream();
            var pout = new PrintStream(out, true, "UTF-8"))
        {
            Main.out = pout;
            Main.err = pout;
            Main.main(args);
            return out.toString(StandardCharsets.UTF_8);
        }
    }

    /**
     * Fails test if first major code in report is not as expected.
     */
    protected void assertFirstMajor(String report, String expectedCode)
    {
        var p = Pattern.compile("<([a-zA-Z]\\w*:)?ResultMajor( [^>]*)?>([^>]*)<");
        var m = p.matcher(report);
        assertThat(m.find()).isTrue();
        assertThat(m.group(3)).endsWith(expectedCode);
    }

    /**
     * Just makes sure that a certain element occurs n times in the report.
     *
     * @param name name of element
     * @param expected number of element of that name
     */
    protected void assertNumberElements(String report, String name, int expected)
    {
        var p = Pattern.compile("<([a-zA-Z]\\w*:)?" + name + "( [^>]*)?>(.+?)</([a-zA-Z]\\w*:)?" + name + ">", Pattern.DOTALL);
        var m = p.matcher(report);
        for (var i = 0; i < expected; i++)
        {
            assertThat(m.find()).isTrue();
        }
        assertThat(m.find()).isFalse();
    }

    /**
     * Provides a temporary file with test data.
     *
     * @param path resource with base64 encoded data
     */
    protected File createDecodedTempFile(String path) throws IOException
    {
        var result = File.createTempFile("testOutput", ".bin");
        result.deleteOnExit();
        try (OutputStream outs = new FileOutputStream(result))
        {
            outs.write(TestUtils.decodeTestResource(path));
        }
        return result;
    }
}
