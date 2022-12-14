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
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;

import java.net.URL;
import java.util.UUID;

import oasis.names.tc.dss._1_0.core.schema.VerifyRequest;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;

import org.junit.Test;

import de.bund.bsi.tr_esor.api._1.S4_Service;
import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;


/**
 * Asserts that the deployed web service can execute a validation.
 *
 * @author HMA, TT
 */
public class WebServiceIT
{

  /**
   * Calls the web service and checks that a verification report is received.
   */
  @Test
  public void callWebService() throws Exception
  {
    var service = new S4_Service(new URL("http://localhost:8080/ErVerifyTool/esor13/exec?wsdl"));
    var port = service.getS4();
    var request = XmlHelper.FACTORY_DSS.createVerifyRequest();
    request.setRequestID(UUID.randomUUID().toString());
    addReturnVR(request, null);
    request.setInputDocuments(XmlHelper.FACTORY_DSS.createInputDocuments());
    var document = XmlHelper.FACTORY_DSS.createDocumentType();
    request.getInputDocuments().getDocumentOrTransformedDataOrDocumentHash().add(document);
    var data = XmlHelper.FACTORY_DSS.createBase64Data();
    document.setBase64Data(data);
    data.setValue(TestUtils.decodeTestResource("/bin/example.tif.b64"));
    data.setMimeType("image/tiff");
    var sig = XmlHelper.FACTORY_DSS.createSignatureObject();
    request.setSignatureObject(sig);
    var sigValue = XmlHelper.FACTORY_DSS.createBase64Signature();
    sig.setBase64Signature(sigValue);
    sigValue.setValue(TestUtils.decodeTestResource("/bin/example.ers.b64"));

    var resp = port.verify(request);

    @SuppressWarnings("unchecked")
    var jaxb = (JAXBElement<VerificationReportType>)resp.getOptionalOutputs().getAny().get(0);
    var report = jaxb.getValue();
    var overallResult = report.getIndividualReport().get(0).getResult();
    assertThat(overallResult.getResultMajor(), endsWith("urn:oasis:names:tc:dss:1.0:detail:indetermined"));
    assertThat(overallResult.getResultMessage().getValue(),
               containsString("atss/0/0/tsp: no online validation of time stamp done"));
    assertThat(overallResult.getResultMessage().getValue(), not(containsString("common#parameterError")));
  }

  private void addReturnVR(VerifyRequest request, String profile) throws JAXBException
  {
    request.setOptionalInputs(XmlHelper.FACTORY_DSS.createAnyType());
    request.setProfile(profile);
    var returnvr = FACTORY_OASIS_VR.createReturnVerificationReport();
    returnvr.setReportDetailLevel("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:reportdetail:allDetails");
    var optIn = XmlHelper.toElement(returnvr, FACTORY_OASIS_VR.getClass().getPackage().getName(), null);
    request.getOptionalInputs().getAny().add(optIn);
  }
}
