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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;


/**
 * Tests the online validation capabilities for time stamps using the eCard protocol.
 *
 * @author MO
 */
public class TestECardTimeStampValidatorIT
{

  private static String eCardURL;

  /**
   * Get the eCard url from the test config
   *
   * @throws Exception
   */
  @BeforeClass
  public static void setUpClass() throws Exception
  {
    TestUtils.loadDefaultConfig();
    eCardURL = Configurator.getInstance()
                           .getValidators("online_profile")
                           .stream()
                           .filter(parser -> "de.bund.bsi.tr_esor.checktool.validation.default_impl.ECardTimeStampValidator".equals(parser.getClassName()))
                           .findAny()
                           .orElseThrow(() -> new IllegalStateException("No profile online_profile with configured ECardTimeStampValidator found!"))
                           .getParameter()
                           .stream()
                           .filter(param -> "eCardURL".equals(param.getName()))
                           .findAny()
                           .orElseThrow(() -> new IllegalStateException("ECardTimeStampValidator does not have an eCardURL parameter configured!"))
                           .getValue();
  }

  /**
   * Asserts that a valid time stamp is checked as valid.
   *
   * @throws Exception
   */
  @Test
  public void testValidTimeStamp() throws Exception
  {
    assumeTrue("ecard webservice", canConnectTo(eCardURL));
    String[] erToTest = {"/xaip/xaip_ok.ers.b64", "/xaip/xaip_ok_sig_ok.ers.b64"};
    for ( String erName : erToTest )
    {
      byte[] erBytes = TestUtils.decodeTestResource(erName);
      EvidenceRecord er = new ASN1EvidenceRecordParser().parse(erBytes);
      ECardTimeStampValidator ectsv = new ECardTimeStampValidator(Collections.singletonMap("eCardURL",
                                                                                           eCardURL));
      ectsv.setContext(new ErValidationContext(new Reference("test timestamp"), "", ""));
      ReportPart report = ectsv.validate(new Reference("test timestamp"),
                                         er.getAtss().get(0).get(0).getTimeStampToken());
      assertThat("validation result for " + erName,
                 report.getOverallResult().getResultMajor(),
                 is(ValidationResultMajor.VALID.toString()));
    }
  }

  /**
   * Asserts that a verification error (not failure!) inside the eCard web service is treated as indetermined
   * result.
   *
   * @throws Exception
   */
  @Test
  public void testErrorFromEcard() throws Exception
  {
    assumeTrue("ecard webservice", canConnectTo(eCardURL));
    ECardTimeStampValidator ectsv = new ECardTimeStampValidator(Collections.singletonMap("eCardURL",
                                                                                         eCardURL));
    TimeStampToken token = Mockito.mock(TimeStampToken.class);
    Mockito.when(token.getEncoded()).thenReturn(new byte[0]);
    byte[] erBytes = TestUtils.decodeTestResource("/xaip/xaip_ok.ers.b64");
    EvidenceRecord er = new ASN1EvidenceRecordParser().parse(erBytes);
    Mockito.when(token.toCMSSignedData())
           .thenReturn(er.getAtss().get(0).get(0).getTimeStampToken().toCMSSignedData());
    ectsv.setContext(new ErValidationContext(new Reference("invalid timestamp"), "", ""));
    ReportPart report = ectsv.validate(new Reference("invalid timestamp"), token);
    assertThat("validation result for invalid timestamp",
               report.getOverallResult().getResultMajor(),
               is(ValidationResultMajor.INDETERMINED.toString()));
    assertThat("validation message for invalid timestamp",
               report.getOverallResult().getResultMessage().getValue(),
               containsString("eCard request failed."));
  }

  /**
   * Asserts that a time stamp with missing revocation information is checked as invalid.
   *
   * @throws Exception
   */
  @Test
  public void testMissingRevocationInformation() throws Exception
  {
    assumeTrue("ecard webservice", canConnectTo(eCardURL));
    String erToTest = "/xaip/xaip_ok.ers.b64";
    byte[] erBytes = TestUtils.decodeTestResource(erToTest);
    EvidenceRecord er = new ASN1EvidenceRecordParser().parse(erBytes);
    TimeStampToken timeStampToken = er.getAtss().get(0).get(0).getTimeStampToken();
    SignerInformationStore sts = stripUnsignedContents(timeStampToken.toCMSSignedData().getSignerInfos());
    CMSSignedData stripped = CMSSignedData.replaceSigners(timeStampToken.toCMSSignedData(), sts);
    ECardTimeStampValidator ectsv = new ECardTimeStampValidator(Collections.singletonMap("eCardURL",
                                                                                         eCardURL));
    ectsv.setContext(new ErValidationContext(new Reference("test timestamp"), "", ""));
    ReportPart report = ectsv.validate(new Reference("test timestamp"), new TimeStampToken(stripped));
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

  private SignerInformationStore stripUnsignedContents(SignerInformationStore signerInfos)
  {
    List<SignerInformation> sigInfo = new ArrayList<>();
    for ( SignerInformation signer : signerInfos.getSigners() )
    {
      sigInfo.add(SignerInformation.replaceUnsignedAttributes(signer, null));
    }
    return new SignerInformationStore(sigInfo);
  }

  private boolean canConnectTo(String url)
  {
    try
    {
      HttpURLConnection connection = null;
      URL lzaURL = new URL(url);
      connection = (HttpURLConnection)lzaURL.openConnection();
      final int timeout = 10_000;
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
