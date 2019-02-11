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
package de.bund.bsi.tr_esor.checktool.validation;

import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import javax.xml.bind.JAXBException;
import javax.xml.transform.dom.DOMSource;

import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Element;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.entry.InputPreparator;
import de.bund.bsi.tr_esor.checktool.entry.ParameterFinder;
import de.bund.bsi.tr_esor.checktool.entry.TestS4VerifyOnly;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.vr._1.EvidenceRecordValidityType;
import de.bund.bsi.tr_esor.vr._1.EvidenceRecordValidityType.ArchiveTimeStampSequence.ArchiveTimeStampChain;
import de.bund.bsi.tr_esor.xaip._1.CredentialType;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Checks that evidence records are located properly in the input data and verification is done for the
 * correct set of data. This test addresses the input preparation as well as the validation itself.
 *
 * @author TT
 */
public class TestErValidation
{

  /**
   * Just provides input data.
   */
  static class DummyParams extends ParameterFinder
  {

    DummyParams()
    {
      setProfileName(null);
      returnVerificationReport = TestUtils.createReturnVerificationReport();
    }

    void setEr(String path) throws IOException
    {
      er = new ASN1EvidenceRecordParser().parse(TestUtils.decodeTestResource(path));
      erRef = new Reference("ER_TEST_VALUE");
    }

    public void setXaip(String path) throws Exception
    {
      try (InputStream ins = TestErValidation.class.getResourceAsStream(path))
      {
        xaip = XmlHelper.parseXaip(ins);
      }
      xaipRef = new Reference("XAIP_TEST_VALUE");
    }

    public void setProfile(String byRequest)
    {
      setProfileName(byRequest);
    }
  }

  /**
   * Loads configuration.
   */
  @BeforeClass
  public static void setUpStatic() throws Exception
  {
    TestUtils.loadDefaultConfig();
  }

  /**
   * Asserts that a report only for an evidence record itself can be created in case the protected data itself
   * is not available. This feature is not required by Feinkonzept.
   * <p>
   * In case protected data objects are given, any hash mismatch will make the ER report invalid. That is
   * tested by the respective entry tests, for instance {@link TestS4VerifyOnly}.
   */
  @Test
  public void testNoProtectedData() throws Exception
  {
    DummyParams params = new DummyParams();
    params.setEr("/cms/er_for_encapsulated_with_er.ers.b64");
    VerificationReportType report = validate(params);
    assertThat("individual reports", report.getIndividualReport(), hasSize(1));
    Result result = report.getIndividualReport().get(0).getResult();
    assertThat("major", result.getResultMajor(), endsWith(":indetermined"));
    assertThat("message",
               result.getResultMessage().getValue(),
               is("atss/0: no protected data to check\natss/0/0/tsp: no online validation of time stamp done"));
  }

  /**
   * Asserts that the report is empty in case no validation was requested.
   */
  @Test
  public void testNoObjectToValidate() throws Exception
  {
    VerificationReportType report = validate(new DummyParams());
    assertThat("individual reports", report.getIndividualReport(), empty());
  }

  /**
   * Asserts that the report contains a meaningful report if the request contains a profile name which is not
   * supported.
   */
  @Test
  public void testProfileNotSupported() throws Exception
  {
    DummyParams params = new DummyParams();
    params.setProfile("foo");
    params.setXaip("/xaip/xaip_ok_ers.xml");
    VerificationReportType report = validate(params);
    assertThat("individual reports", report.getIndividualReport(), hasSize(1));
    Result result = report.getIndividualReport().get(0).getResult();
    assertThat("major", result.getResultMajor(), endsWith(":indetermined"));
    assertThat("minor", result.getResultMinor(), endsWith("#parameterError"));
    assertThat("message", result.getResultMessage().getValue(), is("unsupported profile: foo"));
  }

  private VerificationReportType validate(ParameterFinder params)
    throws ReflectiveOperationException, IOException
  {
    return ValidationScheduler.validate(new InputPreparator(params).getValidations());
  }

  /**
   * Asserts that validation is done for evidence record with more than one TSP in one chain.
   */
  @Test
  public void erAfterReSign() throws Exception
  {
    DummyParams params = new DummyParams();
    params.setXaip("/xaip/xaip_ok_er_resigned.xml");
    VerificationReportType report = validate(params);
    assertThat("individual reports", report.getIndividualReport(), hasSize(1));
    Result result = report.getIndividualReport().get(0).getResult();
    assertThat("major", result.getResultMajor(), endsWith(":indetermined"));
    EvidenceRecordValidityType erValidity = getErValidity(report.getIndividualReport().get(0));
    List<ArchiveTimeStampChain> chain = erValidity.getArchiveTimeStampSequence().getArchiveTimeStampChain();
    assertThat(chain, hasSize(1));
    assertThat(chain.get(0).getArchiveTimeStamp(), hasSize(2));
  }

  /**
   * Asserts that validation is done for evidence record with more than one TSP chain.
   */
  @Test
  public void erAfterRehash() throws Exception
  {
    DummyParams params = new DummyParams();
    params.setEr("/xaip/xaip_ok.rehashed.ers.b64");
    params.setXaip("/xaip/xaip_ok.xml");
    VerificationReportType report = validate(params);
    assertThat("individual reports", report.getIndividualReport(), hasSize(1));
    Result result = report.getIndividualReport().get(0).getResult();
    assertThat("major", result.getResultMajor(), endsWith(":indetermined"));
    EvidenceRecordValidityType erValidity = getErValidity(report.getIndividualReport().get(0));
    assertThat(erValidity.getArchiveTimeStampSequence().getArchiveTimeStampChain(), hasSize(2));
  }


  /**
   * Asserts that a manipulated XAIP is recognized and the message states where the XAIP has been manipulated
   */
  @Test
  public void manipulatedXaip() throws Exception
  {
    DummyParams params = new DummyParams();
    params.setXaip("/xaip/xaip_ok_ers.xml");
    params.getXaip().getMetaDataSection().getMetaDataObject().get(0).setCategory("somethingElse");
    VerificationReportType report = validate(params);
    assertThat("individual reports", report.getIndividualReport(), hasSize(1));
    Result result = report.getIndividualReport().get(0).getResult();
    assertThat("major", result.getResultMajor(), endsWith(":invalid"));
    assertThat("major",
               result.getResultMessage().getValue(),
               anyOf(containsString("Missing digest"), containsString("data2_meta_V001")));
  }


  /**
   * Asserts that several evidence records in one XAIP can be validated and are assigned to the respective
   * version.
   */
  @Test
  public void twoErsInXaip() throws Exception
  {
    DummyParams params = new DummyParams();
    params.setXaip("/xaip/xaip_ok_sig_ers_2version.xml");
    VerificationReportType report = validate(params);
    assertThat("individual reports", report.getIndividualReport(), hasSize(2));
    for ( IndividualReportType indivRep : report.getIndividualReport() )
    {
      assertThat("major", indivRep.getResult().getResultMajor(), endsWith(":indetermined"));
    }
  }

  /**
   * Asserts that a XAIP containing reference to the version manifest for the credential enveloping an
   * evidence record can be validated even if no version ID is set for the evidence record.
   */
  @Test
  public void testErVersionOnlyInRelatedObjects() throws Exception
  {
    DummyParams params = new DummyParams();
    params.setXaip("/xaip/xaip_ok_sig_ers_2version.xml");
    CredentialType erCred = params.getXaip().getCredentialsSection().getCredential().get(1);
    // Manipulate existing XAIP to not contain relatedObjects instead of VersionID
    erCred.getRelatedObjects().add(params.getXaip().getPackageHeader().getVersionManifest().get(1));
    params.getXaip().getCredentialsSection().getCredential().get(1).getEvidenceRecord().setVersionID(null);
    VerificationReportType report = validate(params);
    for ( IndividualReportType indivRep : report.getIndividualReport() )
    {
      assertThat("major", indivRep.getResult().getResultMajor(), endsWith(":indetermined"));
    }
  }

  /**
   * Asserts that a XAIP containing a reference to the version manifest for the credential enveloping an
   * evidence record can be validated.
   */
  @Test
  public void testMatchingErVersionRelatedObjects() throws Exception
  {
    DummyParams params = new DummyParams();
    params.setXaip("/xaip/xaip_ok_ers.xml");
    params.getXaip()
          .getCredentialsSection()
          .getCredential()
          .get(0)
          .getRelatedObjects()
          .add(params.getXaip().getPackageHeader().getVersionManifest().get(0));
    VerificationReportType report = validate(params);
    assertThat("individual reports", report.getIndividualReport(), hasSize(1));
    for ( IndividualReportType indivRep : report.getIndividualReport() )
    {
      assertThat("major", indivRep.getResult().getResultMajor(), endsWith(":indetermined"));
    }
  }

  /**
   * Asserts that a XAIP containing a mismatching reference to the version manifest for the credential
   * enveloping an evidence record is rejected,
   */
  @Test
  public void testMismatchingErVersionRelatedObjects() throws Exception
  {
    DummyParams params = new DummyParams();
    params.setXaip("/xaip/xaip_ok_sig_ers_2version.xml");
    params.getXaip()
          .getCredentialsSection()
          .getCredential()
          .get(1)
          .getRelatedObjects()
          .add(params.getXaip().getPackageHeader().getVersionManifest().get(0));
    VerificationReportType vrt = validate(params);
    Result result = vrt.getIndividualReport().get(1).getResult();
    assertThat("major", result.getResultMajor(), endsWith(":invalid"));
    assertThat("minor", result.getResultMinor(), containsString("parameterError"));
  }

  private EvidenceRecordValidityType getErValidity(IndividualReportType report) throws JAXBException
  {
    assertThat(report.getDetails().getAny(), hasSize(1));
    Element elem = (Element)report.getDetails().getAny().get(0);
    return XmlHelper.parse(new DOMSource(elem),
                           EvidenceRecordValidityType.class,
                           XmlHelper.FACTORY_ESOR_VR.getClass().getPackage().getName());
  }

}
