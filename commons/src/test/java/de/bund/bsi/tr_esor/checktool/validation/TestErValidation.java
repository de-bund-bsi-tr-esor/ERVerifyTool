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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import javax.xml.transform.dom.DOMSource;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import jakarta.activation.DataHandler;
import jakarta.xml.bind.JAXBException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Element;

import com.sun.xml.ws.util.ByteArrayDataSource;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.entry.InputPreparator;
import de.bund.bsi.tr_esor.checktool.entry.ParameterFinder;
import de.bund.bsi.tr_esor.checktool.entry.TestS4VerifyOnly;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.vr.EvidenceRecordValidityType;
import de.bund.bsi.tr_esor.xaip.BinaryMetaDataType;
import de.bund.bsi.tr_esor.xaip.MetaDataObjectType;
import de.bund.bsi.tr_esor.xaip.VersionManifestType;


/**
 * Checks that evidence records are located properly in the input data and verification is done for the
 * correct set of data. This test addresses the input preparation as well as the validation itself.
 */
public class TestErValidation
{

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
    var params = new TestParameterFinder();
    params.setEr("/cms/er_for_encapsulated_with_er.ers.b64");
    var report = validate(params);
    assertThat(report.getIndividualReport(), hasSize(1));
    var result = report.getIndividualReport().get(0).getResult();
    assertThat(result.getResultMajor(), endsWith(":indetermined"));
    assertThat(result.getResultMessage().getValue(),
               is("atss/0: no protected data to check\natss/0/0/tsp: no online validation of time stamp done"));
  }


  /**
   * Asserts that the report is empty in case no validation was requested.
   */
  @Test
  public void testNoObjectToValidate() throws Exception
  {
    var report = validate(new TestParameterFinder());
    assertThat(report.getIndividualReport(), empty());
  }

  /**
   * Asserts that the report contains a meaningful report if the request contains a profile name which is not
   * supported.
   */
  @Test
  public void testProfileNotSupported() throws Exception
  {
    var params = new TestParameterFinder("foo");
    params.setXaip("/xaip/xaip_ok_ers.xml");
    var report = validate(params);
    var erReport = report.getIndividualReport()
                         .stream()
                         .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                         .findAny()
                         .get();
    var result = erReport.getResult();
    assertThat(result.getResultMajor(), endsWith(":indetermined"));
    assertThat(result.getResultMinor(), endsWith("#parameterError"));
    assertThat(result.getResultMessage().getValue(), is("unsupported profile: foo"));
  }

  /**
   * If the LXAIP's data object reference cannot be read expect a parameterError and no further report
   */
  @Test
  public void notReadableProtectedDataInLXaipYieldsToParameterError() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/lxaip/lxaip_wrong_uri.xml");
    var report = validate(params);
    var erReport = report.getIndividualReport()
                         .stream()
                         .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                         .findAny()
                         .get();
    var result = erReport.getResult();
    assertThat(result.getResultMajor(), endsWith(":indetermined"));
    assertThat(result.getResultMessage().getValue(),
               containsString("Cannot read LXAIP's data object (id: HundesteuerAnmeldung_V001) from file"));
    assertThat(result.getResultMinor(), containsString("parameterError"));
  }

  /**
   * If the LXAIP's data object digest value mismatches expect a hashValueMismatch error and no further report
   */
  @Test
  public void brokenIntegrityInLXaipYieldsToValueMismatchError() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/lxaip/lxaip_wrong_digest.xml");
    var report = validate(params);
    var erReport = report.getIndividualReport()
                         .stream()
                         .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                         .findAny()
                         .get();
    var result = erReport.getResult();
    assertThat(result.getResultMajor(), endsWith(":invalid"));
    assertThat(result.getResultMessage().getValue(),
               containsString("The calculated digest value of the LXAIP data object (id: HundesteuerAnmeldung_V001) does not match the embedded digest"));
    assertThat(result.getResultMinor(), containsString("hashValueMismatch"));
  }

  /**
   * Asserts that validation is done for evidence record with more than one TSP in one chain.
   */
  @Test
  public void erAfterReSign() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_er_resigned.xml");
    var report = validate(params);
    var erReport = report.getIndividualReport()
                         .stream()
                         .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                         .findAny()
                         .get();
    var result = erReport.getResult();
    assertThat(result.getResultMajor(), endsWith(":indetermined"));
    var erValidity = getErValidity(report.getIndividualReport().get(0));
    var chain = erValidity.getArchiveTimeStampSequence().getArchiveTimeStampChain();
    assertThat(chain, hasSize(1));
    assertThat(chain.get(0).getArchiveTimeStamp(), hasSize(2));
  }

  /**
   * Asserts that validation is done for evidence record with more than one TSP chain.
   */
  @Test
  public void erAfterRehash() throws Exception
  {
    var params = new TestParameterFinder();
    params.setEr("/xaip/xaip_ok.rehashed.ers.b64");
    params.setXaip("/xaip/xaip_ok.xml");
    var report = validate(params);
    var erReport = report.getIndividualReport()
                         .stream()
                         .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                         .findAny()
                         .get();
    var result = erReport.getResult();
    assertThat(result.getResultMajor(), endsWith(":indetermined"));
    var erValidity = getErValidity(report.getIndividualReport().get(0));
    assertThat(erValidity.getArchiveTimeStampSequence().getArchiveTimeStampChain(), hasSize(2));
  }

  /**
   * Asserts that a manipulated XAIP is recognized and the message states where the XAIP has been manipulated
   */
  @Test
  public void manipulatedXaip() throws Exception
  {
    var params = new TestParameterFinder();
    var binary = new BinaryMetaDataType();
    binary.setValue(new DataHandler(new ByteArrayDataSource("FAKEEEE".getBytes(StandardCharsets.UTF_8),
                                                            "text/plain")));
    params.setXaip("/xaip/xaip_ok_ers.xml");
    params.getXaip().getMetaDataSection().getMetaDataObject().get(0).setBinaryMetaData(binary);
    var report = validate(params);
    var erReport = report.getIndividualReport()
                         .stream()
                         .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                         .findAny()
                         .get();
    var result = erReport.getResult();
    assertThat(result.getResultMajor(), endsWith(":invalid"));
    assertThat(result.getResultMessage().getValue(),
               allOf(containsString("Missing digest"),
                     containsString("metaDataID:Hundename_V001"),
                     containsString("additional protected hash values")));
  }

  /**
   * Asserts that a manipulated XAIP is recognized and the message states where the XAIP has been manipulated
   */
  @Test
  public void missingDataFromXaip() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_ers.xml");
    params.getXaip().getMetaDataSection().getMetaDataObject().remove(0);
    var protectedObjects = params.getXaip()
                                 .getPackageHeader()
                                 .getVersionManifest()
                                 .get(0)
                                 .getPackageInfoUnit()
                                 .get(0)
                                 .getProtectedObjectPointer();
    var versionManifest = protectedObjects.stream()
                                          .filter(o -> o.getValue() instanceof VersionManifestType)
                                          .findFirst();
    var metaData = protectedObjects.stream()
                                   .filter(o -> o.getValue() instanceof MetaDataObjectType)
                                   .findFirst();
    protectedObjects.remove(versionManifest.get());
    protectedObjects.remove(metaData.get());
    var report = validate(params);
    var erReport = report.getIndividualReport()
                         .stream()
                         .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                         .findAny()
                         .get();
    var result = erReport.getResult();
    assertThat(result.getResultMajor(), endsWith(":invalid"));
    assertThat(result.getResultMessage().getValue(),
               allOf(containsString("additional protected hash values"),
                     containsString("Additional hashes:[814d78962b0f8ac2bd63daf9f013ed0c07fe67fbfbfbc152b30a476304a0535d, b976eab293a608a09b13accf570b4fa227ffaf3a10d306ae378248466d057fe3]"),
                     containsString("Expected hashes for: [XAIP_TEST_VALUE/metaDataID:fileSize_V001, XAIP_TEST_VALUE/dataObjectID:HundesteuerAnmeldung_V001]")));
  }

  /**
   * Asserts that an evidence record referring to no version works as long that there is only one version in
   * the xaip
   */
  @Test
  public void versionNotDefined() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_ers.xml");
    params.getXaip().getCredentialsSection().getCredential().get(0).getEvidenceRecord().setVersionID(null);
    var report = validate(params);
    var erReport = report.getIndividualReport()
                         .stream()
                         .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                         .findAny()
                         .get();
    var result = erReport.getResult();
    assertThat(result.getResultMajor(), endsWith(":indetermined"));
  }

  /**
   * Asserts that an evidence record referring to an unknown version is reported as invalid
   */
  @Test
  public void versionNotInXaip() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_ers.xml");
    params.getXaip().getCredentialsSection().getCredential().get(0).getEvidenceRecord().setVersionID("V003");
    var report = validate(params);
    var erReport = report.getIndividualReport()
                         .stream()
                         .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                         .findAny()
                         .get();
    var result = erReport.getResult();
    assertThat(result.getResultMajor(), endsWith(":invalid"));
    assertThat(result.getResultMessage().getValue(),
               allOf(containsString("Cannot find the secured data version referenced by the evidence record:"),
                     containsString("The requested version V003 could not be found in the XAIP."),
                     containsString("Available versions are: [V001]")));
  }

  /**
   * Asserts that several evidence records in one XAIP can be validated and are assigned to the respective
   * version.
   */
  @Test
  public void twoErsInXaip() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_sig_ers_2version.xml");
    var report = validate(params);
    var erReports = report.getIndividualReport()
                          .stream()
                          .filter(irt -> irt.getSignedObjectIdentifier().getFieldName() != null)
                          .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                          .collect(Collectors.toList());
    assertThat(erReports, hasSize(2));
    for ( var indivRep : erReports )
    {
      assertThat(indivRep.getResult().getResultMajor(), endsWith(":indetermined"));
    }
  }

  /**
   * Asserts that a XAIP containing two version manifests and an ER not pointing to any version can not be
   * validated.
   */
  @Test
  public void testNoVersionDefinedInErWithMoreThanOneVersionManifest() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_sig_ers_2version.xml");
    var erCred = params.getXaip()
                       .getCredentialsSection()
                       .getCredential()
                       .stream()
                       .filter(x -> "ER_2.16.840.1.101.3.4.2.1_V002".equals(x.getCredentialID()))
                       .findAny()
                       .get();
    erCred.getEvidenceRecord().setVersionID(null);
    var report = validate(params);
    var result = report.getIndividualReport()
                       .stream()
                       .filter(x -> "XAIP_TEST_VALUE/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V002".equals(x.getSignedObjectIdentifier()
                                                                                                            .getFieldName()))
                       .findAny()
                       .get()
                       .getResult();
    assertThat(result.getResultMajor(), endsWith(":invalid"));
    assertThat(result.getResultMinor(), containsString("parameterError"));
    assertThat(result.getResultMessage().getValue(),
               containsString("There is more than one VersionManifest in the Xaip. The EvidenceRecord needs to specify which version it relates to."));
  }

  /**
   * Asserts that a XAIP containing reference to the version manifest for the credential enveloping an
   * evidence record can be validated even if no version ID is set for the evidence record.
   */
  @Test
  public void testErVersionOnlyInRelatedObjects() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_sig_ers_2version.xml");
    var erCred = params.getXaip().getCredentialsSection().getCredential().get(2);
    // Manipulate existing XAIP to not contain relatedObjects instead of VersionID
    erCred.getRelatedObjects().add(params.getXaip().getPackageHeader().getVersionManifest().get(0));
    params.getXaip().getCredentialsSection().getCredential().get(2).getEvidenceRecord().setVersionID(null);
    var report = validate(params);
    for ( var indivRep : report.getIndividualReport() )
    {
      assertThat(indivRep.getResult().getResultMajor(), endsWith(":indetermined"));
    }
  }

  /**
   * Asserts that a XAIP containing reference to two version manifest for the credential enveloping an
   * evidence record can not be validated.
   */
  @Test
  public void testErVersionInRelatedObjectsPointsToTwoVersionManifests() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_sig_ers_2version.xml");
    var erCred = params.getXaip()
                       .getCredentialsSection()
                       .getCredential()
                       .stream()
                       .filter(x -> "ER_2.16.840.1.101.3.4.2.1_V002".equals(x.getCredentialID()))
                       .findAny()
                       .get();
    erCred.getRelatedObjects().add(params.getXaip().getPackageHeader().getVersionManifest().get(1));
    erCred.getRelatedObjects().add(params.getXaip().getPackageHeader().getVersionManifest().get(0));
    erCred.getEvidenceRecord().setVersionID(null);
    var report = validate(params);
    var result = report.getIndividualReport()
                       .stream()
                       .filter(x -> "XAIP_TEST_VALUE/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V002".equals(x.getSignedObjectIdentifier()
                                                                                                            .getFieldName()))
                       .findAny()
                       .get()
                       .getResult();
    assertThat(result.getResultMajor(), endsWith(":invalid"));
    assertThat(result.getResultMinor(), containsString("parameterError"));
    assertThat(result.getResultMessage().getValue(),
               containsString("An EvidenceRecord can only refer to one VersionManifest."));
  }

  /**
   * Asserts that a XAIP containing reference to a dataObject instead of a version manifest for the credential
   * enveloping an evidence record can not be validated.
   */
  @Test
  public void testErVersionInRelatedObjectsPointsToDataObject() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_ers.xml");
    var erCred = params.getXaip().getCredentialsSection().getCredential().get(0);
    erCred.getEvidenceRecord().setVersionID(null);
    erCred.getRelatedObjects().add(params.getXaip().getDataObjectsSection().getDataObject().get(0));
    var report = validate(params);
    var result = report.getIndividualReport().get(0).getResult();
    assertThat(result.getResultMajor(), endsWith(":invalid"));
    assertThat(result.getResultMinor(), containsString("parameterError"));
    assertThat(result.getResultMessage().getValue(),
               containsString("None of the relatedObjects of the given EvidenceRecord are referring to a VersionManifest"));
  }

  /**
   * Asserts that a XAIP containing a reference to the version manifest for the credential enveloping an
   * evidence record can be validated.
   */
  @Test
  public void testMatchingErVersionRelatedObjects() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_ers.xml");
    params.getXaip()
          .getCredentialsSection()
          .getCredential()
          .get(0)
          .getRelatedObjects()
          .add(params.getXaip().getPackageHeader().getVersionManifest().get(0));
    var report = validate(params);
    var erReports = report.getIndividualReport()
                          .stream()
                          .filter(irt -> irt.getSignedObjectIdentifier().getFieldName() != null)
                          .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                          .collect(Collectors.toList());
    assertThat(erReports, hasSize(1));
    for ( var indivRep : erReports )
    {
      assertThat(indivRep.getResult().getResultMajor(), endsWith(":indetermined"));
    }
  }

  /**
   * Asserts that a XAIP containing a mismatching reference to the version manifest for the credential
   * enveloping an evidence record is rejected.
   */
  @Test
  public void testMismatchingErVersionRelatedObjects() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_sig_ers_2version.xml");
    params.getXaip()
          .getCredentialsSection()
          .getCredential()
          .stream()
          .filter(x -> "ER_2.16.840.1.101.3.4.2.1_V002".equals(x.getCredentialID()))
          .findAny()
          .get()
          .getRelatedObjects()
          .add(params.getXaip().getPackageHeader().getVersionManifest().get(0));
    var vrt = validate(params);
    var result = vrt.getIndividualReport()
                    .stream()
                    .filter(x -> "XAIP_TEST_VALUE/evidenceRecord:ER_2.16.840.1.101.3.4.2.1_V002".equals(x.getSignedObjectIdentifier()
                                                                                                         .getFieldName()))
                    .findAny()
                    .get()
                    .getResult();
    assertThat(result.getResultMajor(), endsWith(":invalid"));
    assertThat(result.getResultMinor(), containsString("parameterError"));
    assertThat(result.getResultMessage().getValue(),
               containsString("Version ID for EvidenceRecord and relatedObjects reference in enveloping credential do not match"));
  }

  /**
   * Asserts that several evidence records in one XAIP can be validated and are assigned to the respective
   * version.
   */
  @Test
  public void manyCredentialsInXAIP() throws Exception
  {
    var params = new TestParameterFinder();
    params.setXaip("/xaip/xaip_ok_ers_multiple_credentials.xml");
    var report = validate(params);
    var erReport = report.getIndividualReport()
                         .stream()
                         .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
                         .findAny()
                         .get();
    var result = erReport.getResult();
    assertThat(result.getResultMajor(), endsWith(":indetermined"));
  }

  private VerificationReportType validate(ParameterFinder params)
    throws ReflectiveOperationException, IOException
  {
    return ValidationScheduler.validate(new InputPreparator(params).getValidations());
  }

  private EvidenceRecordValidityType getErValidity(IndividualReportType report) throws JAXBException
  {
    assertThat(report.getDetails().getAny(), hasSize(1));
    var elem = (Element)report.getDetails().getAny().get(0);
    return XmlHelper.parse(new DOMSource(elem),
                           EvidenceRecordValidityType.class,
                           XmlHelper.FACTORY_ESOR_VR.getClass().getPackage().getName());
  }

}
