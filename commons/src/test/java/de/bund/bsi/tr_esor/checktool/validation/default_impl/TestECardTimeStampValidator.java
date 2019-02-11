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

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_DSS;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_ECARD;
import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.function.Supplier;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.transform.stream.StreamSource;
import javax.xml.ws.WebServiceException;

import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import de.bund.bsi.ecard.api._1.ECard;
import de.bund.bsi.ecard.api._1.ECard_Service;
import de.bund.bsi.ecard.api._1.VerifyResponse;
import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.BasisErsECardTimeStampValidator;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.InternationalStringType;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.DetailedSignatureReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Offline checks for ECardTimeStampValidator.
 *
 * @author MO
 */
public class TestECardTimeStampValidator
{

  /**
   * The result of the time stamp report depends on the occurrence of format violations. An "indetermined"
   * result is overwritten by an "invalid" result if the format is invalid. The format of the used time stamp
   * token is expected to be valid as defined by RFC4998.
   */
  protected boolean expectInvalidFormat = false;

  /**
   * Expected exception.
   */
  @Rule
  public ExpectedException exp = ExpectedException.none();

  /**
   * Tests for errors with illegal URL values.
   *
   * @throws Exception
   */
  @Test
  public void testInvalidURL() throws Exception
  {
    exp.expect(IllegalArgumentException.class);
    createSystemUnderTest("not an url");
  }

  /**
   * Tests for unreachable eCard responder.
   *
   * @throws Exception
   */
  @Test
  public void testUnreachableResponder() throws Exception
  {
    TimeStampToken tst = createTimeStampToken();
    ECardTimeStampValidator validator = createSystemUnderTest("http://unreachable:8080/eCard/eCard?wsdl");
    validator.setContext(new ErValidationContext(new Reference("dummy"), "", ""));
    ReportPart result = validator.validate(new Reference("dummy"), tst);
    assertThat("report message", result.toString(), containsString("eCard webservice is unreachable"));
  }

  /**
   * Asserts that a {@link BasisErsECardTimeStampValidator} translates findings of eCard response into its
   * report.
   *
   * @throws JAXBException
   * @throws IOException
   */
  @Test
  public void updateCodes() throws JAXBException, IOException
  {
    ECardTimeStampValidator systemUnderTest = createSystemUnderTest("http://ignored");
    Reference ref = new Reference("tsp");
    try (InputStream ins = TestECardTimeStampValidator.class.getResourceAsStream("/tspReport.xml"))
    {
      String ctxPath = FACTORY_OASIS_VR.getClass().getPackage().getName();
      VerificationReportType vr = XmlHelper.parse(new StreamSource(ins),
                                                  VerificationReportType.class,
                                                  ctxPath);
      AnyType any = FACTORY_DSS.createAnyType();
      any.getAny().add(FACTORY_OASIS_VR.createVerificationReport(vr));

      TimeStampReport report = systemUnderTest.getTSReportFromAny(any, ref, new TimeStampReport(ref));
      assertThat(report.getOverallResult().getResultMajor(), endsWith(":invalid"));
      assertThat(report.getSummarizedMessage(), containsString("some original message"));
      assertThat(report.getFormatted().getCertificatePathValidity(), not(nullValue()));
    }
  }

  /**
   * Asserts that error codes are mapped correctly when eCard reports an internal error.
   *
   * @throws Exception
   */
  @Test
  public void reportInternalError() throws Exception
  {
    Reference ref = new Reference("dummy");
    String errMsg = "something went wrong";
    TimeStampToken tst = createTimeStampToken();
    ECard ecard = mock(ECard.class);
    ECardTimeStampValidator systemUnderTest = createSystemUnderTestWith(ecard);
    systemUnderTest.setContext(new ErValidationContext(ref, "", ""));

    VerifyResponse response = FACTORY_ECARD.createVerifyResponse();
    Result result = FACTORY_DSS.createResult();
    response.setResult(result);

    result.setResultMajor("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error");
    result.setResultMinor("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError");
    InternationalStringType message = FACTORY_DSS.createInternationalStringType();
    message.setLang("en");
    message.setValue(errMsg);
    result.setResultMessage(message);

    when(ecard.verifyRequest(any())).thenReturn(response);
    TimeStampReport report = systemUnderTest.validate(ref, tst);

    assertThat(report.getOverallResult().getResultMajor(),
               is("urn:oasis:names:tc:dss:1.0:detail:" + (expectInvalidFormat ? "invalid" : "indetermined")));
    assertThat(report.getOverallResult().getResultMinor(),
               expectInvalidFormat //
                 ? is("http://www.bsi.bund.de/tr-esor/api/1.2/resultminor/invalidFormat")
                 : is("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError"));
    assertThat(report.getOverallResult().getResultMessage().getValue(),
               is("eCard request failed. Response error was: " + errMsg));
  }

  /**
   * Asserts that a meaningful report is returned when the eCard service is unreachable.
   *
   * @throws Exception
   */
  @Test
  public void reportUnreachable() throws Exception
  {
    Reference ref = new Reference("dummy");
    String errMsg = "something went wrong";
    TimeStampToken tst = createTimeStampToken();
    ECard ecard = mock(ECard.class);
    ECardTimeStampValidator systemUnderTest = createSystemUnderTestWith(ecard);
    systemUnderTest.setContext(new ErValidationContext(ref, "", ""));

    when(ecard.verifyRequest(any())).thenThrow(new WebServiceException(errMsg));
    TimeStampReport report = systemUnderTest.validate(ref, tst);

    assertThat(report.getOverallResult().getResultMajor(),
               endsWith(expectInvalidFormat ? ":invalid" : ":indetermined"));
    assertThat(report.getOverallResult().getResultMinor(),
               endsWith(expectInvalidFormat ? "/invalidFormat" : "#internalError"));
    assertThat(report.getOverallResult().getResultMessage().getValue(),
               is("eCard webservice is unreachable. Message was: " + errMsg));
  }

  /**
   * Asserts that the validator reports meaningful messages in case that the used eCard does not respond
   * properly.
   *
   * @throws Exception
   */
  @Test
  public void reportIllegalECardResponses() throws Exception
  {
    assumeFalse("test only for valid format", expectInvalidFormat);
    final JAXBElement<DetailedSignatureReportType> elementWithWrongType = FACTORY_OASIS_VR.createDetailedSignatureReport(new DetailedSignatureReportType());

    reportIllegalOptionalOutput("Did not get exactly one OptionalOutput element as expected.",
                                () -> FACTORY_DSS.createAnyType());
    reportIllegalOptionalOutput("OptionalOutput element from eCard response could not be parsed.", //
                                () -> {
                                  AnyType any = FACTORY_DSS.createAnyType();
                                  any.getAny().add("cannotBeParsed");
                                  return any;
                                });
    reportIllegalOptionalOutput("OptionalOutput element is not a VerificationReportType.", //
                                () -> {
                                  AnyType any = FACTORY_DSS.createAnyType();
                                  any.getAny().add(elementWithWrongType);
                                  return any;
                                });
    reportIllegalVerificationReport("Did not get exactly one IndividualReport element as expected.",
                                    () -> FACTORY_OASIS_VR.createVerificationReportType());
    reportIllegalVerificationReport("IndividualReport element does not contain details.", //
                                    () -> {
                                      VerificationReportType vr = FACTORY_OASIS_VR.createVerificationReportType();
                                      vr.getIndividualReport()
                                        .add(FACTORY_OASIS_VR.createIndividualReportType());
                                      return vr;
                                    });
    reportIllegalDetails("Details of IndividualReport element does not contain exactly one element as expected.",
                         () -> FACTORY_DSS.createAnyType());
    reportIllegalDetails("Details of IndividualReport element OptionalOutput element could not be parsed.",
                         () -> {
                           AnyType details = FACTORY_DSS.createAnyType();
                           details.getAny().add("cannotBeParsed");
                           return details;
                         });
    reportIllegalDetails("Details of IndividualReport element is not a TimeStampValidityType.", //
                         () -> {
                           AnyType details = FACTORY_DSS.createAnyType();
                           details.getAny().add(elementWithWrongType);
                           return details;
                         });
  }

  /**
   * Asserts that the validator reports the given message for the given OptionalOutput which is responded by
   * eCard.
   *
   * @param message
   * @param optionalOutput
   * @throws Exception
   */
  private void reportIllegalOptionalOutput(String message, Supplier<AnyType> optionalOutput) throws Exception
  {
    Reference ref = new Reference("dummy");
    TimeStampToken tst = createTimeStampToken();
    ECard ecard = mock(ECard.class);
    ECardTimeStampValidator systemUnderTest = createSystemUnderTestWith(ecard);
    systemUnderTest.setContext(new ErValidationContext(ref, "", ""));

    VerifyResponse response = FACTORY_ECARD.createVerifyResponse();
    Result result = FACTORY_DSS.createResult();
    result.setResultMajor("http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok");
    response.setResult(result);
    response.setOptionalOutputs(optionalOutput.get());

    when(ecard.verifyRequest(any())).thenReturn(response);
    TimeStampReport report = systemUnderTest.validate(ref, tst);

    assertThat(report.getOverallResult().getResultMajor(),
               is("urn:oasis:names:tc:dss:1.0:detail:indetermined"));
    assertThat(report.getOverallResult().getResultMinor(),
               is("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError"));
    assertThat(report.getOverallResult().getResultMessage().getValue(),
               is("Illegal eCard response. " + message));

  }

  private TimeStampToken createTimeStampToken() throws IOException
  {
    byte[] erBytes = TestUtils.decodeTestResource("/bin/example.ers.b64");
    EvidenceRecord er = new ASN1EvidenceRecordParser().parse(erBytes);
    return er.getAtss().get(0).get(0).getTimeStampToken();
  }

  /**
   * Asserts that the validator reports the given message for the given VerificationReport which is responded
   * by eCard.
   *
   * @param message
   * @param optionalOutput
   * @throws Exception
   */
  private void reportIllegalVerificationReport(String message, Supplier<VerificationReportType> vr)
    throws Exception
  {
    AnyType any = new AnyType();
    any.getAny().add(FACTORY_OASIS_VR.createVerificationReport(vr.get()));
    reportIllegalOptionalOutput(message, () -> any);
  }

  /**
   * Asserts that the validator reports the given message for the given IndividualReport details which are
   * responded by eCard.
   *
   * @param message
   * @param optionalOutput
   * @throws Exception
   */
  private void reportIllegalDetails(String message, Supplier<AnyType> details) throws Exception
  {
    VerificationReportType vr = FACTORY_OASIS_VR.createVerificationReportType();
    IndividualReportType ir = FACTORY_OASIS_VR.createIndividualReportType();
    ir.setDetails(details.get());
    vr.getIndividualReport().add(ir);
    reportIllegalVerificationReport(message, () -> vr);
  }

  /**
   * Returns new instance of the system which is under test and configured by the given URL.
   *
   * @param url
   */
  protected ECardTimeStampValidator createSystemUnderTest(String url)
  {
    return new ECardTimeStampValidator(Collections.singletonMap("eCardURL", url));
  }

  private ECardTimeStampValidator createSystemUnderTestWith(ECard ecard)
  {
    ECardTimeStampValidator systemUnderTest = createSystemUnderTest("http://ignored");
    systemUnderTest.eCardWebService = when(mock(ECard_Service.class).getECard()).thenReturn(ecard).getMock();
    return systemUnderTest;
  }

}
