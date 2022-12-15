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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
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
@SuppressWarnings("PMD.AvoidDuplicateLiterals")
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

    var report = callMain("-conf",
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

    var report = callMain("-conf", RES_DIR + "config.xml", "-data", RES_DIR + "xaip/xaip_ok_ers.xml");
    assertThat("report", report, containsString("SAMLv2Identifier>urn:Beispiel</"));
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "InsufficientInformation");
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
    var report = callMain("-conf",
                          RES_DIR + "config.xml",
                          "-data",
                          RES_DIR + "/xaip/xaip_ok.xml",
                          "-er",
                          RES_DIR + "/xaip/xaip_ok.er.xml");
    assertThat("report", report, containsString("SAMLv2Identifier>urn:Beispiel</"));
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "InsufficientInformation");
  }

  /**
   * Asserts that a standard detached ER can be verified in the Basis-ERS profile
   *
   * @throws IOException
   */
  @Test
  public void usingBasisErsProfile() throws IOException
  {
    var report = callMain("-conf",
                          RES_DIR + "config.xml",
                          "-profile",
                          "Basis-ERS",
                          "-data",
                          RES_DIR + "/xaip/xaip_ok.xml",
                          "-er",
                          RES_DIR + "/xaip/xaip_ok.er.xml");
    assertThat("report", report, containsString("SAMLv2Identifier>urn:Beispiel</"));
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "InsufficientInformation");
  }

  /**
   * Asserts that an evidence record for a XAIP given separately can be validated.
   * <p>
   * See TR-ESOR-ERS-FEIN p. 23 UC1.1/1.2 paragraph 2.
   *
   * @throws IOException
   */
  @Test
  public void detachedErForLXaip() throws IOException
  {
    var report = callMain("-conf",
                          RES_DIR + "config.xml",
                          "-data",
                          RES_DIR + "/lxaip/lxaip_ok.xml",
                          "-er",
                          RES_DIR + "/lxaip/lxaip_ok.ers.xml");
    assertThat("report", report, containsString("SAMLv2Identifier>urn:Beispiel</"));
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "InsufficientInformation");
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
    var data = createDecodedTempFile("/cms/encapsulated_with_er.p7s.b64");
    var report = callMain("-conf", RES_DIR + "config.xml", "-er", data.getAbsolutePath());
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "InsufficientInformation");
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
    var data = createDecodedTempFile("/cms/TestDataLogo.png.b64").getAbsolutePath();
    var ers = createDecodedTempFile("/cms/TestDataLogo.png_er.p7s.b64").getAbsolutePath();

    var report = callMain("-conf", RES_DIR + "config.xml", "-data", data, "-er", ers);
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "InsufficientInformation");

    // negative case:
    report = callMain("-conf", RES_DIR + "config.xml", "-data", RES_DIR + "config.xml", "-er", ers);
    assertNumberElements(report, "ReducedHashTree", 1);
    assertFirstMajor(report, "RequesterError");
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
    var ers = createDecodedTempFile("/bin/er_nok_wrong_version.er.b64").getAbsolutePath();
    var report = callMain("-conf", RES_DIR + "config.xml", "-er", ers);
    assertFirstMajor(report, "RequesterError");
    assertThat("the invalidFormat result minor is contained in the report",
               report,
               containsString("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/invalidFormat"));
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
    var data = createDecodedTempFile("/bin/example.tif.b64").getAbsolutePath();
    var ers = createDecodedTempFile("/bin/example.ers.b64").getAbsolutePath();

    for ( var erPath : new String[]{ers, RES_DIR + "bin/example.er.xml"} )
    {
      var report = callMain("-conf", RES_DIR + "config.xml", "-data", data, "-er", erPath);
      assertNumberElements(report, "IndividualReport", 1);
      assertNumberElements(report, "ArchiveTimeStamp", 1);
      assertFirstMajor(report, "InsufficientInformation");
    }
  }

  /**
   * Asserts that binary contents extracted from a XAIP can be checked against the ER generated for the whole
   * XAIP.
   */
  @Test
  public void erFromXaipWithBinOnly() throws IOException
  {
    // Binary data from xaip_ok
    var dataFile = File.createTempFile("Hundename_V001", ".bin");
    dataFile.deleteOnExit();
    try (OutputStream outs = new FileOutputStream(dataFile))
    {
      outs.write("TestData".getBytes(StandardCharsets.US_ASCII));
    }

    var erPath = createDecodedTempFile("/xaip/xaip_ok.ers.b64").getAbsolutePath();

    var report = callMain("-conf",
                          RES_DIR + "config.xml",
                          "-data",
                          dataFile.getAbsolutePath(),
                          "-er",
                          erPath);
    assertFirstMajor(report, "InsufficientInformation");
    assertThat("There is no mismatch detected",
               report,
               not(containsString("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/hashValueMismatch")));
    assertThat("No error message",
               report,
               not(containsString("The evidence record contains additional protected hash values")));
    assertNumberElements(report, "IndividualReport", 1);
    assertNumberElements(report, "ArchiveTimeStamp", 1);
    assertNumberElements(report, "HashValue", 4);
  }

  /**
   * Assert that a message is displayed if configuration is not valid.
   */
  @Test
  public void invalidConfig() throws IOException
  {
    var msg = callMain("-conf", "build.gradle");
    assertThat("Message after loading bad config",
               msg,
               containsString("Config file build.gradle is not valid XML."));
  }

  /**
   * Asserts that an unsupported format of ER value is reported. Major code will be "RequesterError" because
   * we only know that the application does not support that value. Report must not contain details because
   * application does not know details for what.
   */
  @Test
  public void verifyInvalidErParam() throws Exception
  {
    var report = callMain("-conf", RES_DIR + "config.xml", "-er", RES_DIR + "config.xml");
    assertThat("report", report, containsString("ResponderError"));
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
    var xaipPath = "/xaip/xaip_ok.xml";
    var erPath = "/bin/mock_wrong_version.er.xml";

    var report = callMain("-conf",
                          RES_DIR + "config.xml",
                          "-data",
                          RES_DIR + xaipPath,
                          "-er",
                          RES_DIR + erPath);

    assertThat("report", report, IsValidXML.matcherForValidVerificationReport());

    assertFirstMajor(report, "RequesterError");
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
    var xaipPath = "/xaip/xaip_ok_2_er_resigned.xml";
    var erPath = "/bin/mock_wrong_version.er.xml";

    var report = callMain("-conf",
                          RES_DIR + "config.xml",
                          "-data",
                          RES_DIR + xaipPath,
                          "-er",
                          RES_DIR + erPath);

    assertThat("report", report, IsValidXML.matcherForValidVerificationReport());
    assertFirstMajor(report, "RequesterError");
    assertThat("report",
               report,
               containsString("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError"));
    assertThat("report", report, containsString("Given XAIP does not match AOID"));
  }

  /**
   * Asserts that the validation of an evidence record that contains an invalid CMS version leads to a clear
   * and understandable error message. The test data is an otherwise valid ER where only the CMS version of
   * the first timestamp has been manipulated.
   */
  @Test
  public void wrongCmsVersionInDetachedEr() throws Exception
  {
    var data = createDecodedTempFile("/bin/example.tif.b64").getAbsolutePath();
    var ers = createDecodedTempFile("/bin/example_wrong_cms_version.ers.b64").getAbsolutePath();

    var report = callMain("-conf", RES_DIR + "config.xml", "-data", data, "-er", ers);

    assertFirstMajor(report, "RequesterError");
    assertNumberElements(report, "IndividualReport", 1);
    assertNumberElements(report, "ArchiveTimeStamp", 1);
    assertThat("report", report, IsValidXML.matcherForValidVerificationReport());
    assertThat("report",
               report,
               containsString("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/invalidFormat"));
    assertThat("report", report, containsString("Invalid CMS version 1 in timestamp"));
  }

  /**
   * Checks report validity when hashes are not sorted(according to RFC 4998) and are sorted.
   *
   * @throws Exception
   */
  @Test
  public void checkSortedHashValidation() throws Exception
  {
    var report = callMain("-conf",
                          RES_DIR + "config.xml",
                          "-profile",
                          "sorted",
                          "-data",
                          RES_DIR + "/sorted/XAIP_SORTED_SHA512_GOVTSP.xml");
    assertThat("report", report, IsValidXML.matcherForValidVerificationReport());
    assertThat("report",
               report,
               not(containsString("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/hashValueMismatch")));

    var report2 = callMain("-conf",
                           RES_DIR + "config.xml",
                           "-profile",
                           "unsorted",
                           "-data",
                           RES_DIR + "/sorted/XAIP_SORTED_SHA512_GOVTSP.xml");
    assertThat("report", report2, IsValidXML.matcherForValidVerificationReport());
    assertFirstMajor(report, "InsufficientInformation");
    assertThat("report",
               report2,
               containsString("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/hashValueMismatch"));
    assertThat("report",
               report2,
               containsString("The hashes present in the evidence record do not match the mode (sorted/unsorted) given by the configuration."));
    assertThat("report",
               report2,
               containsString("The hashes present seem to conform to the sorted hash mode."));
    assertThat("report", report2, not(containsString("Missing digest(s) for:")));
    assertThat("report", report2, not(containsString("additional protected hash values")));
  }

  /**
   * Assert that the "both" mode for the hashMode-Parameter can check both hashing types.
   */
  @Test
  public void checkValidationUsingBothHashMode() throws Exception
  {
    var reportSorted = callMain("-conf",
                                RES_DIR + "config.xml",
                                "-profile",
                                "both",
                                "-data",
                                RES_DIR + "/sorted/XAIP_SORTED_SHA512_GOVTSP.xml");
    assertThat("report", reportSorted, IsValidXML.matcherForValidVerificationReport());
    assertFirstMajor(reportSorted, "InsufficientInformation");
    assertThat("report", reportSorted, not(containsString("hashValueMismatch")));
    assertThat("report", reportSorted, not(containsString("Missing digest(s) for:")));
    assertThat("report", reportSorted, not(containsString("additional protected hash values")));
    assertThat("report", reportSorted, not(containsString("do not match the mode (sorted/unsorted)")));

    var reportUnsorted = callMain("-conf",
                                  RES_DIR + "config.xml",
                                  "-profile",
                                  "both",
                                  "-data",
                                  RES_DIR + "/xaip/xaip_ok.xml",
                                  "-er",
                                  RES_DIR + "/xaip/xaip_ok.rehashed.ers.b64");
    assertThat("report", reportUnsorted, IsValidXML.matcherForValidVerificationReport());
    assertFirstMajor(reportUnsorted, "InsufficientInformation");
    assertThat("report", reportUnsorted, not(containsString("hashValueMismatch")));
    assertThat("report", reportUnsorted, not(containsString("Missing digest(s) for:")));
    assertThat("report", reportUnsorted, not(containsString("additional protected hash values")));
    assertThat("report", reportUnsorted, not(containsString("do not match the mode (sorted/unsorted)")));
  }

  /**
   * Asserts that a verification report stating that no online validation was possible can be obtained.
   */
  @Test
  public void signatureInXaip() throws IOException
  {
    var data = RES_DIR + "xaip/signature/xaip_ok_sig.xml";
    var report = callMain("-conf", RES_DIR + "config.xml", "-data", data);
    assertThat("report", report, containsString("SAMLv2Identifier>urn:Beispiel</"));
    assertThat("report",
               report,
               containsString("No online validation of a potential signature was possible"));
    assertFirstMajor(report, "InsufficientInformation");
  }

  /**
   * Assert that presenting an unsupported XAIP version is detected
   */
  @Test
  public void checkUnsupportedXaipVersion() throws Exception
  {
    var report = callMain("-conf", RES_DIR + "config.xml", "-data", RES_DIR + "/xaip/esor12/xaip_ok.xml");
    assertFirstMajor(report, "ResponderError");
    assertThat("report", report, containsString("illegal or unsupported data format"));
  }

  /**
   * Assert that a XAIP using non-exclusive xml canonicalization can be validated.
   */
  @Test
  public void checkNonExclusiveCanonicalization() throws Exception
  {
    var report = callMain("-conf",
                          RES_DIR + "config.xml",
                          "-data",
                          RES_DIR + "/xaip/xaip_xml_meta.xml",
                          "-er",
                          RES_DIR + "/xaip/xaip_xml_meta.ers");
    assertFirstMajor(report, "InsufficientInformation");
    assertThat("report",
               report,
               containsString("ResultMessage xml:lang=\"en\">atss/0/0/tsp: no online validation of time stamp done</"));
  }

  /**
   * Asserts that namespaces are not rewritten on a XAIP that uses namespaces other than the default
   */
  @Test
  public void checkNonDefaultNamespacesAccepted() throws IOException
  {
    var report = callMain("-conf",
                          RES_DIR + "config.xml",
                          "-data",
                          RES_DIR + "xaip/xaip_ok_ers_namespace.xml");
    assertThat("report", report, containsString("SAMLv2Identifier>urn:Beispiel</"));
    assertThat("report", report, not(containsString("hashValueMismatch")));
    assertFirstMajor(report, "InsufficientInformation");
  }

  /**
   * Asserts that S4 web server can be started using the command line parameters "-server" and "-port".
   */
  @Test(timeout = 30_000)
  public void callServer() throws Exception
  {
    final var port = 9876;
    assumeAddressNotInUse("localhost", port);
    var msg = callMain("-conf", RES_DIR + "config.xml", "-server", "-port", "9876");
    assertThat(msg,
               startsWith("Running S4 webservice on address http://localhost:9876/ErVerifyTool/esor13/exec"));
    checkConnection("http://localhost:9876/ErVerifyTool/esor13/exec?wsdl");
  }

  /**
   * Assumes that host and port are free so we can start the web server.
   *
   * @param host
   * @param port
   */
  private void assumeAddressNotInUse(String host, int port)
  {
    try (var socket = SocketFactory.getDefault().createSocket(host, port))
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
  @SuppressWarnings({"boxing", "PMD.DataflowAnomalyAnalysis"})
  private void checkConnection(String address)
  {
    HttpURLConnection connection = null;
    try
    {
      var url = new URL(address);
      connection = (HttpURLConnection)url.openConnection();
      final var timeout = 1_000;
      connection.setConnectTimeout(timeout);
      connection.setReadTimeout(timeout);
      connection.connect();
      assertEquals(HttpURLConnection.HTTP_OK, connection.getResponseCode());
      try (var is = connection.getInputStream(); var isr = new InputStreamReader(is, StandardCharsets.UTF_8);)
      {
        final var bufSize = 1024;
        var cbuf = new char[bufSize];
        assertThat("number read bytes", isr.read(cbuf), greaterThan(1));
        assertThat(String.valueOf(cbuf),
                   containsString("targetNamespace=\"http://www.bsi.bund.de/tr-esor/api/1.3\" name=\"S4\""));
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
