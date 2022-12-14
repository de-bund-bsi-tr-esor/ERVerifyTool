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
package de.bund.bsi.tr_esor.checktool.validation.default_impl;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.hamcrest.CoreMatchers;
import org.junit.BeforeClass;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;


/**
 * Tests the online validation capabilities for timestamps using the eCard. This isolated test cannot
 * reproduce the actual behaviour, where the timestamp's hash source is determined when all validators work
 * together. This is why we here can test for indetermined at best for a valid timestamp. Other tests ensure
 * online validation can result in valid results.
 */
public class TestECardTimeStampValidatorIT
{

  private static String eCardURL;

  @BeforeClass
  public static void setUpClass() throws Exception
  {
    TestUtils.loadDefaultConfig();
    eCardURL = Configurator.getInstance().getVerificationServiceURL("TR-ESOR");
    assumeTrue(canConnectTo(eCardURL));
  }

  /**
   * Asserts that a valid time stamp is checked as indetermined at best because the source data is missing.
   */
  @Test
  public void testValidTimeStamp() throws Exception
  {
    var erToTest = new String[]{"/xaip/xaip_ok.ers.b64", "/xaip/xaip_ok_sig_ok.ers.b64"};
    for ( var erName : erToTest )
    {
      TimeStampReport report = validateErFromRessources(erName, "custom");
      assertThat(report.getOverallResult().getResultMajor(),
                 is(ValidationResultMajor.INDETERMINED.toString()));
      assertThat(report.getSummarizedMessage(), containsString("detached_content_file_missing"));
    }
  }

  /**
   * Asserts that a test time stamp is checked as invalid if the TR-ESOR profile requiring qualified
   * timestamps is selected
   */
  @Test
  public void refusesNonQualifiedTimestamp() throws Exception
  {
    TimeStampReport report = validateErFromRessources("/xaip/xaip_ok.ers.b64", "TR-ESOR");
    assertThat(report.getOverallResult().getResultMajor(), is(ValidationResultMajor.INVALID.toString()));
    assertThat(TestECardTimeStampValidator.extractChainingOkMessage(report),
               CoreMatchers.containsString("The quality of the certificate chain for the timestamp was determined as: "));
    assertThat(report.getSummarizedMessage(),
               containsString("A checked timestamp should be qualified, but the quality of the timestamp was determined as: "));
  }

  private TimeStampReport validateErFromRessources(String testResource, String profileName) throws IOException
  {
    var erBytes = TestUtils.decodeTestResource(testResource);
    var er = new ASN1EvidenceRecordParser().parse(erBytes);
    var sut = new ECardTimeStampValidator();
    sut.setContext(new ErValidationContext(new Reference("timestamp"), "", profileName));
    return sut.validate(new Reference("timestamp"), er.getAtss().get(0).get(0).getTimeStampToken());
  }

  /**
   * Asserts that a qualified time stamp is checked as indetermined if the TR-ESOR profile requiring qualified
   * timestamps is selected, but no data is given. Also asserts quality information is added to the report.
   */
  @Test
  public void acceptsQualifiedTimestamp() throws Exception
  {
    TimeStampReport report = validateErFromRessources("/xaip/xaip_ok_qualified.ers.b64", "TR-ESOR");
    assertThat(report.getOverallResult().getResultMajor(), is(ValidationResultMajor.INDETERMINED.toString()));
    assertThat(report.getSummarizedMessage(), containsString("detached_content_file_missing"));
    assertThat(TestECardTimeStampValidator.extractChainingOkMessage(report),
               allOf(CoreMatchers.containsString("The quality of the certificate chain for the timestamp was determined as: "),
                     CoreMatchers.containsString("QTST_EUMS_TL")));
  }

  /**
   * Asserts that a time stamp with missing revocation information is checked as invalid.
   */
  @Test
  public void testMissingRevocationInformation() throws Exception
  {
    var erToTest = "/xaip/xaip_ok.ers.b64";
    var erBytes = TestUtils.decodeTestResource(erToTest);
    var er = new ASN1EvidenceRecordParser().parse(erBytes);
    var timeStampToken = er.getAtss().get(0).get(0).getTimeStampToken();
    var stripped = CMSSignedData.replaceCertificatesAndCRLs(timeStampToken.toCMSSignedData(),
                                                            null,
                                                            timeStampToken.getAttributeCertificates(),
                                                            null);
    var sut = new ECardTimeStampValidator();
    sut.setContext(new ErValidationContext(new Reference("test timestamp"), "", "custom"));
    var report = sut.validate(new Reference("test timestamp"), new TimeStampToken(stripped));
    assertThat("validation result major for tsp with missing revocation",
               report.getOverallResult().getResultMajor(),
               is(ValidationResultMajor.INVALID.toString()));
    assertThat("validation result minor for tsp with missing revocation",
               report.getOverallResult().getResultMinor(),
               containsString("invalidFormat"));
    assertThat("validation result message for tsp with missing revocation",
               report.getSummarizedMessage(),
               containsString("Missing revocation info in time stamp"));
  }

  private static boolean canConnectTo(String url)
  {
    try
    {
      var connection = (HttpURLConnection)new URL(url).openConnection();
      var timeout = 10_000;
      connection.setConnectTimeout(timeout);
      connection.setReadTimeout(timeout);
      connection.connect();
      return HttpURLConnection.HTTP_OK == connection.getResponseCode();
    }
    catch (IOException e)
    {
      return false;
    }
  }

}
