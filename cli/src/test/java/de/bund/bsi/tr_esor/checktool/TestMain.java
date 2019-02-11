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
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import javax.net.SocketFactory;

import org.junit.AssumptionViolatedException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.entry.IsValidXML;
import de.bund.bsi.tr_esor.checktool.entry.TestS4VerifyOnly;


/**
 * Unit test for the main class only. For actual verification, see tests of the respective classes. Tests in
 * this class must make sure that in each use case the input given to the command line is forwarded to the
 * validation subcomponent. Whether the validations are done properly is checked in the tests of the commons
 * project. This test does not perform XML schema checks of the output because that is done by
 * {@link TestS4VerifyOnly}.
 * <p>
 * Note that successful validation without online check of TSPs (certificates) can result only in
 * "indetermined".
 *
 * @author TT
 */
public class TestMain extends TestBase
{

  private static final Logger LOG = LoggerFactory.getLogger(TestMain.class);

  private static final String NEW_LINE = System.getProperty("line.separator");

  /**
   * Asserts that invalid command line parameters are reported in a suitable form.
   *
   * @throws IOException
   */
  @Test
  public void invalidParameters() throws IOException
  {
    assertThat("wrong param", callMain("-hepl"), is("Unrecognized option: -hepl" + NEW_LINE));
    assertThat("missing argument", callMain("-conf"), is("Missing argument for option: conf" + NEW_LINE));
    assertThat("conf file not found",
               callMain("-conf", "/jibbetnich"),
               startsWith("Config file /jibbetnich not readable"));
  }

  /**
   * Asserts that a verification report contains a sensible message in case of unknown profile. Actual
   * validation is not done in this case.
   *
   * @throws IOException
   */
  @Test
  public void unknownProfile() throws IOException
  {

    String report = callMain("-conf",
                             RES_DIR + "config.xml",
                             "-data",
                             RES_DIR + "/xaip/xaip_ok_ers.xml",
                             "-profile",
                             "unknown");
    assertThat("report", report, containsString("Unsupported profile"));
    assertThat("report", report, containsString("  https://tools.ietf.org/html/rfc4998\n"));
  }

  /**
   * Asserts that a verification report with some details can be obtained via command line for an evidence
   * record embedded within a XAIP.
   * <p>
   * See TR-ESOR-ERS-FEIN p. 23 UC1.1/1.2 paragraph 1.
   *
   * @throws IOException
   */
  @Test
  public void erInXaip() throws IOException
  {

    String report = callMain("-conf", RES_DIR + "config.xml", "-data", RES_DIR + "xaip/xaip_ok_ers.xml");
    assertThat("report", report, containsString("SAMLv2Identifier>urn:Beispiel</"));
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "indetermined");
  }

  /**
   * Asserts that an evidence record for a XAIP given separately can be validated.
   * <p>
   * See TR-ESOR-ERS-FEIN p. 23 UC1.1/1.2 paragraph 2.
   *
   * @throws IOException
   */
  @Test
  public void detachedErForXaip() throws IOException
  {
    String report = callMain("-conf",
                             RES_DIR + "config.xml",
                             "-data",
                             RES_DIR + "/xaip/xaip_ok.xml",
                             "-er",
                             RES_DIR + "/xaip/xaip_ok.er.xml");
    assertThat("report", report, containsString("SAMLv2Identifier>urn:Beispiel</"));
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "indetermined");
  }

  /**
   * Asserts that an evidence record embedded into an encapsulated CMS structure can be validated.
   * <p>
   * See TR-ESOR-ERS-FEIN p. 23 UC1.1/1.2 paragraph 3. <br>
   *
   * @throws IOException
   */
  @Test
  public void erInCmsEncapsulated() throws IOException
  {
    File data = createDecodedTempFile("/cms/encapsulated_with_er.p7s.b64");
    String report = callMain("-conf", RES_DIR + "config.xml", "-er", data.getAbsolutePath());
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "indetermined");
  }

  /**
   * Asserts that an evidence record embedded into a detached CMS structure can be validated. To make sure
   * that the data attribute is covered, we include a negative test giving wrong data.
   * <p>
   * See TR-ESOR-ERS-FEIN p. 23 UC1.1/1.2 paragraph 3. <br>
   *
   * @throws IOException
   */
  @Test
  public void erInCmsDetached() throws IOException
  {
    String data = createDecodedTempFile("/cms/TestDataLogo.png.b64").getAbsolutePath();
    String ers = createDecodedTempFile("/cms/TestDataLogo.png_er.p7s.b64").getAbsolutePath();

    String report = callMain("-conf", RES_DIR + "config.xml", "-data", data, "-er", ers);
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "indetermined");

    // negative case:
    report = callMain("-conf", RES_DIR + "config.xml", "-data", RES_DIR + "config.xml", "-er", ers);
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "invalid");
  }

  /**
   * Asserts the tool can take an ASN1-encoded evidence record containing a version number other than 1 and
   * returns invalid as a result as other versions are not supported according to the specification.
   *
   * @throws IOException
   */
  @Test
  public void erInvalidVersion() throws IOException
  {
    String ers = createDecodedTempFile("/bin/er_nok_wrong_version.er.b64").getAbsolutePath();
    String report = callMain("-conf", RES_DIR + "config.xml", "-er", ers);
    assertFirstMajor(report, "invalid");
    assertThat("the invalidFormat result minor is contained in the report",
               report,
               containsString("http://www.bsi.bund.de/tr-esor/api/1.2/resultminor/invalidFormat"));
    assertThat("an unexpected version number message is included in the report",
               report,
               containsString("unexpected version number"));
  }

  /**
   * Asserts that an evidence record can be validated against a binary content. See TR-ESOR-ERS-FEIN p. 23
   * UC1.1/1.2 paragraph 4.
   * <p>
   * The checks are executed twice: the evidence record is given as ASN.1 encoded binary file or within an XML
   * file.
   *
   * @throws IOException
   */
  @Test
  public void erForBinary() throws IOException
  {
    String data = createDecodedTempFile("/bin/example.tif.b64").getAbsolutePath();
    String ers = createDecodedTempFile("/bin/example.ers.b64").getAbsolutePath();

    for ( String erPath : new String[]{ers, RES_DIR + "bin/example.er.xml"} )
    {
      String report = callMain("-conf", RES_DIR + "config.xml", "-data", data, "-er", erPath);
      assertNumberElements(report, "IndividualReport", 1);
      assertNumberElements(report, "ArchiveTimeStamp", 1);
      assertFirstMajor(report, "indetermined");
    }
  }

  /**
   * Assert that a message is displayed if configuration is not valid.
   */
  @Test
  public void invalidConfig() throws IOException
  {
    String msg = callMain("-conf", "build.gradle");
    assertThat("Message after loading bad config",
               msg,
               containsString("Config file build.gradle is not valid XML."));
  }

  /**
   * Asserts that an unsupported format of ER value is reported. Major code will be "indetermined" because we
   * only know that the application does not support that value. Report must not contain details because
   * application does not know details for what.
   */
  @Test
  public void verifyInvalidErParam() throws Exception
  {
    String report = callMain("-conf", RES_DIR + "config.xml", "-er", RES_DIR + "config.xml");
    assertThat("report", report, containsString("urn:oasis:names:tc:dss:1.0:detail:indetermined"));
    assertThat("report", report, containsString("resultminor/invalidFormat"));
    assertThat("report", report, not(containsString("Details")));
  }

  /**
   * Asserts that validation of a XML together with an evidence record specifying a wrong version results in a
   * VerificationReport containing an individual report stating the verification was impossible and resulted
   * in an invalid result and no error is printed to the console.
   */
  @Test
  public void wrongXaipVersion() throws Exception
  {
    String xaipPath = "/xaip/xaip_ok.xml";
    String erPath = "/bin/mock_wrong_version.er.xml";

    String report = callMain("-conf",
                             RES_DIR + "config.xml",
                             "-data",
                             RES_DIR + xaipPath,
                             "-er",
                             RES_DIR + erPath);

    assertThat("report", report, IsValidXML.isValidVerificationReport());

    assertFirstMajor(report, "invalid");
    assertThat("report",
               report,
               containsString("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError"));
    assertThat("report",
               report,
               containsString("Given XAIP does not contain version V003 addressed in xaip:evidenceRecord."));
  }

  /**
   * Asserts that validation of a XML together with an evidence record specifying a wrong AOID results in a
   * VerificationReport containing an individual report stating the verification was impossible and resulted
   * in an invalid result and no error is printed to the console.
   */
  @Test
  public void wrongAoidInDetachedEr() throws Exception
  {
    String xaipPath = "/xaip/xaip_ok_er_resigned.xml";
    String erPath = "/bin/mock_wrong_version.er.xml";

    String report = callMain("-conf",
                             RES_DIR + "config.xml",
                             "-data",
                             RES_DIR + xaipPath,
                             "-er",
                             RES_DIR + erPath);

    assertThat("report", report, IsValidXML.isValidVerificationReport());

    assertFirstMajor(report, "invalid");
    assertThat("report",
               report,
               containsString("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError"));
    assertThat("report", report, containsString("Given XAIP does not match AOID"));
  }

  /**
   * Asserts that S4 web server can be started using the command line parameters "-server" and default port.
   */
  @Test(timeout = 5_000)
  public void callServerWithDefaultPort() throws Exception
  {
    final int port = 9999;
    assumeAddressNotInUse("localhost", port);
    String msg = callMain("-conf", RES_DIR + "config.xml", "-server");
    assertThat(msg, is("Running S4 webservice on address http://localhost:9999/ErVerifyTool/esor12/exec\n"));
    checkConnection("http://localhost:9999/ErVerifyTool/esor12/exec?wsdl");
  }

  /**
   * Asserts that S4 web server can be started using the command line parameters "-server" and "-port".
   */
  @Test(timeout = 5_000)
  public void callServerWithSpecificPort() throws Exception
  {
    final int port = 9876;
    assumeAddressNotInUse("localhost", port);
    String msg = callMain("-conf", RES_DIR + "config.xml", "-server", "-port", "9876");
    assertThat(msg, is("Running S4 webservice on address http://localhost:9876/ErVerifyTool/esor12/exec\n"));
    checkConnection("http://localhost:9876/ErVerifyTool/esor12/exec?wsdl");
  }

  /**
   * Assumes that host and port are free so we can start the web server.
   *
   * @param host
   * @param port
   */
  private void assumeAddressNotInUse(String host, int port)
  {
    try (Socket socket = SocketFactory.getDefault().createSocket(host, port))
    {
      throw new AssumptionViolatedException(host + ":" + port + " is already in use");
    }
    catch (IOException e)
    {
      LOG.debug("expected exception", e);
    }
  }

  /**
   * Opens a connection to the given address and asserts that a S4 WSDL is responded.
   *
   * @param address
   */
  @SuppressWarnings("boxing")
  private void checkConnection(String address)
  {
    HttpURLConnection connection = null;
    try
    {
      URL url = new URL(address);
      connection = (HttpURLConnection)url.openConnection();
      final int timeout = 1_000;
      connection.setConnectTimeout(timeout);
      connection.setReadTimeout(timeout);
      connection.connect();
      assertEquals(HttpURLConnection.HTTP_OK, connection.getResponseCode());
      try (InputStream is = connection.getInputStream();
        InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);)
      {
        final int bufSize = 1024;
        char[] cbuf = new char[bufSize];
        assertThat("number read bytes", isr.read(cbuf), greaterThan(1));
        assertThat(String.valueOf(cbuf),
                   containsString("targetNamespace=\"http://www.bsi.bund.de/tr-esor/api/1.2\" name=\"S4\""));
      }
    }
    catch (IOException e)
    {
      fail(e.getMessage());
    }
    finally
    {
      if (connection != null)
      {
        connection.disconnect();
      }
    }
  }

}
