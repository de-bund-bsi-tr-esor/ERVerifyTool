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

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;

import java.net.URL;
import java.util.UUID;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import org.junit.Test;
import org.w3c.dom.Element;

import de.bund.bsi.tr_esor.api._1.S4;
import de.bund.bsi.tr_esor.api._1.S4_Service;
import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import oasis.names.tc.dss._1_0.core.schema.Base64Data;
import oasis.names.tc.dss._1_0.core.schema.Base64Signature;
import oasis.names.tc.dss._1_0.core.schema.DocumentType;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss._1_0.core.schema.SignatureObject;
import oasis.names.tc.dss._1_0.core.schema.VerifyRequest;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Asserts that the deployed web service can execute a validation.
 *
 * @author HMA, TT
 */
public class WebServiceIT
{

  /**
   * Calls the web service and checks that a verification report is received.
   *
   * @throws Exception
   */
  @Test
  public void callWebService() throws Exception
  {
    S4_Service service = new S4_Service(new URL("http://localhost:8080/ErVerifyTool/esor12/exec?wsdl"));
    S4 port = service.getS4();
    VerifyRequest request = XmlHelper.FACTORY_DSS.createVerifyRequest();
    request.setRequestID(UUID.randomUUID().toString());
    addReturnVR(request, null);
    request.setInputDocuments(XmlHelper.FACTORY_DSS.createInputDocuments());
    DocumentType document = XmlHelper.FACTORY_DSS.createDocumentType();
    request.getInputDocuments().getDocumentOrTransformedDataOrDocumentHash().add(document);
    Base64Data data = XmlHelper.FACTORY_DSS.createBase64Data();
    document.setBase64Data(data);
    data.setValue(TestUtils.decodeTestResource("/bin/example.tif.b64"));
    data.setMimeType("image/tiff");
    SignatureObject sig = XmlHelper.FACTORY_DSS.createSignatureObject();
    request.setSignatureObject(sig);
    Base64Signature sigValue = XmlHelper.FACTORY_DSS.createBase64Signature();
    sig.setBase64Signature(sigValue);
    sigValue.setValue(TestUtils.decodeTestResource("/bin/example.ers.b64"));

    ResponseBaseType resp = port.verify(request);

    @SuppressWarnings("unchecked")
    JAXBElement<VerificationReportType> jaxb = (JAXBElement<VerificationReportType>)resp.getOptionalOutputs()
                                                                                        .getAny()
                                                                                        .get(0);
    VerificationReportType report = jaxb.getValue();
    Result overallResult = report.getIndividualReport().get(0).getResult();
    assertThat(overallResult.getResultMajor(), endsWith("urn:oasis:names:tc:dss:1.0:detail:indetermined"));
    assertThat(overallResult.getResultMessage().getValue(),
               containsString("atss/0/0/tsp: no online validation of time stamp done"));
  }

  private void addReturnVR(VerifyRequest request, String profile) throws JAXBException
  {
    request.setOptionalInputs(XmlHelper.FACTORY_DSS.createAnyType());
    request.setProfile(profile);
    ReturnVerificationReport returnvr = FACTORY_OASIS_VR.createReturnVerificationReport();
    returnvr.setReportDetailLevel("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:reportdetail:allDetails");
    Element optIn = XmlHelper.toElement(returnvr, FACTORY_OASIS_VR.getClass().getPackage().getName(), null);
    request.getOptionalInputs().getAny().add(optIn);
  }
}
