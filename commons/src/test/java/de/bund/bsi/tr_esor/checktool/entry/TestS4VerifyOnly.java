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
package de.bund.bsi.tr_esor.checktool.entry;

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ESOR_VR;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_XAIP;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;
import java.util.function.Consumer;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;

import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.parser.EvidenceRecordTypeParser;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.vr._1.EvidenceRecordValidityType;
import de.bund.bsi.tr_esor.xaip._1.XAIPType;
import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.Base64Data;
import oasis.names.tc.dss._1_0.core.schema.Base64Signature;
import oasis.names.tc.dss._1_0.core.schema.DocumentType;
import oasis.names.tc.dss._1_0.core.schema.InlineXMLType;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss._1_0.core.schema.SignatureObject;
import oasis.names.tc.dss._1_0.core.schema.VerifyRequest;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Just calls the web service method to make sure the delegation is done correctly. This test must check that
 * in each use case, the web service parameter are forwarded correctly to the validation sub-component and a
 * report is returned. Whether the validation itself is done correctly is checked by the test classes in
 * package "validation".
 *
 * @author TT
 */
public class TestS4VerifyOnly
{

  /**
   * Loads configuration.
   *
   * @throws Exception
   */
  @BeforeClass
  public static void setUpStatic() throws Exception
  {
    TestUtils.loadDefaultConfig();
  }

  /**
   * Asserts that an evidence record embedded within a XAIP is validated and a report is returned. Calls the
   * verify operation (without setting a profile) and asserts that a verifier has been called. Checks schema
   * validity of report.
   *
   * @throws Exception to occur in the test report
   */
  @Test
  public void verifyErEmbeddedInXaip() throws Exception
  {

    callVerify(r -> {
      addReturnVR(r, null, ReportDetailLevel.NO_DETAILS);
      addXaip(r, "xaip_ok_ers.xml");
    }, "indetermined", false);

  }

  /**
   * Asserts that a verify request without an returnVerificationReport Parameter can be called without
   * problems.
   *
   * @throws Exception to occur in the test report
   */
  @Test
  public void verifyWithoutReturnVR() throws Exception
  {
    VerificationReportType verificationReport = callVerify(r -> {
      addXaip(r, "xaip_ok_ers.xml");
    }, "indetermined", false);
    assertThat("VerificationReport is filled", verificationReport, is(nullValue()));
  }

  /**
   * Asserts that a detached evidence record for some XAIP can be validated.
   *
   * @throws Exception
   */
  @Test
  public void verifyErForXaip() throws Exception
  {
    callVerify(r -> {
      addReturnVR(r, null, ReportDetailLevel.ALL_DETAILS);
      addXaip(r, "xaip_ok.xml");
      setBase64SignatureObject("/xaip/xaip_ok.ers.b64", r);
    }, "indetermined", true);
  }

  /**
   * Asserts that a detached evidence record for some XAIP can be validated.
   *
   * @throws Exception
   */
  @Test
  public void verifyErInXmlForXaip() throws Exception
  {
    callVerify(r -> {
      addReturnVR(r, null, ReportDetailLevel.ALL_DETAILS);
      addXaip(r, "xaip_ok.xml");
      setXmlSignatureObject("/xaip/xaip_ok.er.xml", r);
    }, "indetermined", true);
  }

  /**
   * Asserts that validation results in invalid in case the XML containing the evidence record specifies a
   * wrong version or AOID.
   */
  @Test
  public void wrongXaipVersionsOrAOID() throws Exception
  {
    VerifyRequest request = XmlHelper.FACTORY_DSS.createVerifyRequest();
    request.setRequestID(UUID.randomUUID().toString());
    addXaip(request, "xaip_ok.xml");
    setXmlSignatureObject("/xaip/xaip_ok.er.xml", request);
    Element xaipErs = (Element)request.getSignatureObject().getOther().getAny().get(0);
    xaipErs.setAttribute("VersionID", "V003");
    ResponseBaseType resp = new S4VerifyOnly().verify(request);
    assertThat(resp.getResult().getResultMajor(), is("urn:oasis:names:tc:dss:1.0:detail:invalid"));
    assertThat(resp.getResult().getResultMessage().getValue(),
               is("Given XAIP does not contain version V003 addressed in xaip:evidenceRecord."));
    xaipErs.setAttribute("AOID", "wrongAOID");
    resp = new S4VerifyOnly().verify(request);
    assertThat(resp.getResult().getResultMajor(), is("urn:oasis:names:tc:dss:1.0:detail:invalid"));
    assertThat(resp.getResult().getResultMessage().getValue(),
               is("Given XAIP does not match AOID wrongAOID addressed in xaip:evidenceRecord."));
  }

  /**
   * Sends encapsulated CMS signed data with embedded record as signature object. Asserts that evidence record
   * is checked. Asserts that the result becomes invalid if accidentally some non-secure data is added to the
   * request.
   *
   * @throws Exception
   */
  @Test
  public void verifyErForEncapsulatedCms() throws Exception
  {
    checkForBinaryData("/cms/encapsulated_with_er.p7s.b64", null, "indetermined");
    checkForBinaryData("/cms/encapsulated_with_er.p7s.b64", "/cms/TestDataLogo.png.b64", "invalid");
  }

  /**
   * Sends detached CMS signed data with embedded record as signature object. Asserts that evidence record is
   * checked.
   *
   * @throws Exception
   */
  @Test
  public void verifyErForDetachedCms() throws Exception
  {
    checkForBinaryData("/cms/TestDataLogo.png_er.p7s.b64", "/cms/TestDataLogo.png.b64", "indetermined");
    // now with some data file not containing signed data
    checkForBinaryData("/cms/TestDataLogo.png_er.p7s.b64", "/cms/TestDataLogo.png_er.p7s.b64", "invalid");
  }

  /**
   * Asserts that an evidence record for some binary content can be validated.
   *
   * @throws Exception
   */
  @Test
  public void verifyErForBinary() throws Exception
  {
    checkForBinaryData("/bin/example.ers.b64", "/bin/example.tif.b64", "indetermined");
  }

  /**
   * Calls verification (with explicit RFC4998 profile) against binary data but signature object cannot be
   * parsed. Assures schema validity of report. No detail report can be given because there is no ER to
   * verify.
   */
  @Test
  public void verifyInvalidAsn1() throws Exception
  {
    VerificationReportType report = callVerify(r -> {
      addReturnVR(r, ProfileNames.RFC4998, ReportDetailLevel.ALL_DETAILS);
      setBase64SignatureObject("/bin/example.tif.b64", r);
      addBinaryData("/bin/example.tif.b64", r);
    }, "indetermined", false);
    assertThat("message",
               report.getIndividualReport().get(0).getResult().getResultMessage().getValue(),
               is("illegal or unsupported data format"));
  }

  /**
   * Asserts that an internal error is responded in case of invalid configuration. Checking that behavior is
   * necessary in case the application is deployed on some application server.
   *
   * @throws Exception
   */
  @Test
  public void invalidConfiguration() throws Exception
  {
    try
    {
      Configurator.getInstance().load(null);
      assertFalse("invalid config", Configurator.getInstance().isLoaded());
    }
    catch (IllegalArgumentException e)
    {
      assertThat("error message", e.getMessage(), containsString("must not be null"));
    }
    try
    {
      VerifyRequest request = XmlHelper.FACTORY_DSS.createVerifyRequest();
      request.setRequestID(UUID.randomUUID().toString());
      addReturnVR(request, null, ReportDetailLevel.ALL_DETAILS);
      addXaip(request, "xaip_ok_ers.xml");

      ResponseBaseType resp = new S4VerifyOnly().verify(request);
      Result result = resp.getResult();
      assertThat(result.getResultMajor(), is("urn:oasis:names:tc:dss:1.0:detail:invalid"));
      assertThat(result.getResultMinor(),
                 is("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError"));
      assertThat(result.getResultMessage().getValue(), is("system has not been configured correctly"));
    }
    finally
    {
      setUpStatic(); // restore valid configuration
      assertTrue("valid config restored", Configurator.getInstance().isLoaded());
    }
  }

  /**
   * Asserts that no other web service method than <code>verify</code> is supported.
   */
  @Test
  public void unsupportedOperation()
  {
    S4VerifyOnly s4 = new S4VerifyOnly();
    assertUnsupported("archiveData", () -> s4.archiveData(null));
    assertUnsupported("archiveDeletion", () -> s4.archiveDeletion(null));
    assertUnsupported("archiveEvidence", () -> s4.archiveEvidence(null));
    assertUnsupported("archiveRetrieval", () -> s4.archiveRetrieval(null));
    assertUnsupported("archiveSubmission", () -> s4.archiveSubmission(null));
    assertUnsupported("archiveUpdate", () -> s4.archiveUpdate(null));
  }

  /**
   * Just a macro for sending a request
   *
   * @param sigObjectPath
   * @param dataPath
   * @throws Exception
   */
  private VerificationReportType checkForBinaryData(String sigObjectPath,
                                                    String dataPath,
                                                    String expectedMajor)
    throws Exception
  {
    return callVerify(r -> {
      addReturnVR(r, null, ReportDetailLevel.ALL_DETAILS);
      setBase64SignatureObject(sigObjectPath, r);
      if (dataPath != null)
      {
        addBinaryData(dataPath, r);
      }
    }, expectedMajor, true);
  }

  /**
   * Macro for building the request, calling verification and generic check of report.
   *
   * @param fillRequest
   * @param expectedMajor
   * @return obtained report for further checks.
   * @throws Exception
   */
  private VerificationReportType callVerify(Consumer<VerifyRequest> fillRequest,
                                            String expectedMajor,
                                            boolean expectDetails)
    throws Exception
  {
    VerifyRequest request = XmlHelper.FACTORY_DSS.createVerifyRequest();
    request.setRequestID(UUID.randomUUID().toString());
    fillRequest.accept(request);

    ResponseBaseType resp = new S4VerifyOnly().verify(request);
    assertThat(resp.getRequestID(), is(request.getRequestID()));
    if (request.getOptionalInputs() != null)
    {

      VerificationReportType report = getAndCheckVerificationReport(resp);
      assertThat("individual reports", report.getIndividualReport(), hasSize(1));
      if (expectDetails)
      {
        Object detail = report.getIndividualReport().get(0).getDetails().getAny().get(0);
        assertThat("ER validity",
                   ((JAXBElement<?>)detail).getValue(),
                   instanceOf(EvidenceRecordValidityType.class));
      }
      assertThat("major",
                 report.getIndividualReport().get(0).getResult().getResultMajor(),
                 endsWith(":" + expectedMajor));
      return report;
    }
    return null;
  }

  private void assertUnsupported(String label, Runnable action)
  {
    try
    {
      action.run();
      fail(label + " must be unsupported");
    }
    catch (UnsupportedOperationException e)
    {
      assertThat(e.getMessage(), is("only archiveVerify operation is supported by this tool"));
    }
  }

  private DocumentType newDocument(VerifyRequest request)
  {
    if (request.getInputDocuments() == null)
    {
      request.setInputDocuments(XmlHelper.FACTORY_DSS.createInputDocuments());
    }
    DocumentType document = XmlHelper.FACTORY_DSS.createDocumentType();
    request.getInputDocuments().getDocumentOrTransformedDataOrDocumentHash().add(document);
    return document;
  }

  private void addBinaryData(String path, VerifyRequest request)
  {
    DocumentType document = newDocument(request);
    Base64Data value = XmlHelper.FACTORY_DSS.createBase64Data();
    value.setValue(TestUtils.decodeTestResource(path));
    document.setBase64Data(value);
  }

  private void setXmlSignatureObject(String path, VerifyRequest r)
  {
    SignatureObject sigObject = XmlHelper.FACTORY_DSS.createSignatureObject();
    try (InputStream res = TestS4VerifyOnly.class.getResourceAsStream(path);
      InputStream ins = new BufferedInputStream(res))
    {
      EvidenceRecordTypeParser parser = new EvidenceRecordTypeParser();
      parser.setInput(ins);
      AnyType any = XmlHelper.FACTORY_DSS.createAnyType();
      Element element = XmlHelper.toElement(parser.parse(),
                                            FACTORY_XAIP.getClass().getPackage().getName(),
                                            FACTORY_XAIP::createEvidenceRecord);
      any.getAny().add(element);
      sigObject.setOther(any);
    }
    catch (IOException | JAXBException e)
    {
      fail(e.getMessage());
    }
    r.setSignatureObject(sigObject);
  }

  private void setBase64SignatureObject(String path, VerifyRequest request)
  {
    SignatureObject sigObject = XmlHelper.FACTORY_DSS.createSignatureObject();
    Base64Signature ers = XmlHelper.FACTORY_DSS.createBase64Signature();
    ers.setType("urn:ingnored:asn1ER");
    ers.setValue(TestUtils.decodeTestResource(path));
    sigObject.setBase64Signature(ers);
    request.setSignatureObject(sigObject);
  }

  private void addReturnVR(VerifyRequest request, String profile, ReportDetailLevel reportDetailLevel)
  {
    try
    {
      request.setOptionalInputs(XmlHelper.FACTORY_DSS.createAnyType());
      request.setProfile(profile);
      ReturnVerificationReport returnvr = FACTORY_OASIS_VR.createReturnVerificationReport();
      returnvr.setReportDetailLevel(reportDetailLevel.toString());
      Element optIn = XmlHelper.toElement(returnvr, FACTORY_OASIS_VR.getClass().getPackage().getName(), null);
      request.getOptionalInputs().getAny().add(optIn);
    }
    catch (JAXBException e)
    {
      fail("cannot serialize returnVR: " + e);
    }
  }

  /**
   * Returns the verification report in a response, asserts that it exists and satisfies XML schema.
   *
   * @param resp
   * @throws Exception
   */
  private VerificationReportType getAndCheckVerificationReport(ResponseBaseType resp) throws Exception
  {
    assertThat(resp.getOptionalOutputs().getAny(), hasSize(1));
    Element vrElement = (Element)resp.getOptionalOutputs().getAny().get(0);
    String path = FACTORY_OASIS_VR.getClass().getPackage().getName() + ":"
                  + FACTORY_ESOR_VR.getClass().getPackage().getName();
    VerificationReportType report = XmlHelper.parse(new DOMSource(vrElement),
                                                    VerificationReportType.class,
                                                    path);
    assertNotNull("parsed verification report", report);
    String reportAsString = TestUtils.toString(FACTORY_OASIS_VR.createVerificationReport(report), path);
    assertThat(reportAsString, IsValidXML.isValidVerificationReport());
    return report;
  }

  /**
   * Adds a XAIP to the verify request.
   *
   * @param request
   * @param fileName
   * @throws IOException
   * @throws JAXBException
   */
  private void addXaip(VerifyRequest request, String fileName)
  {
    DocumentType document = newDocument(request);

    InlineXMLType inlineXMLType = XmlHelper.FACTORY_DSS.createInlineXMLType();
    document.setInlineXML(inlineXMLType);
    try (InputStream ins = TestS4VerifyOnly.class.getResourceAsStream("/xaip/" + fileName))
    {
      inlineXMLType.setAny(toElement(XmlHelper.parseXaip(ins)));
    }
    catch (IOException | JAXBException e)
    {
      fail("parsing XAIP: " + e);
    }
  }

  /**
   * Simulates that content of any-elements arrives in the deployed web service as element.
   *
   * @param xaip
   * @throws JAXBException
   */
  private Element toElement(XAIPType xaip) throws JAXBException
  {
    JAXBContext ctx = JAXBContext.newInstance(FACTORY_XAIP.getClass().getPackage().getName());
    DOMResult result = new DOMResult();
    ctx.createMarshaller().marshal(FACTORY_XAIP.createXAIP(xaip), result);
    return ((Document)result.getNode()).getDocumentElement();
  }
}
