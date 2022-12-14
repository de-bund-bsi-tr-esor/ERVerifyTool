/*-
 * Copyright (c) 2019
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
package de.bund.bsi.tr_esor.checktool.validation.signatures;

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;
import static org.assertj.core.api.Assertions.assertThat;

import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss._1_0.core.schema.ResponseBaseType;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import jakarta.xml.bind.JAXBElement;

import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.SignatureReportPart;


/**
 * Unit test class for {@link BaseECardSignatureValidator}
 *
 * @author PRE, ETR
 */
public class TestBaseECardSignatureValidator
{

  public static final String TEST = "test";

  /**
   * Asserts that report is filled with indetermined result code because of passed given result message.
   */
  @Test
  public void fillInIndetermined()
  {
    var report = new SignatureReportPart(new Reference(TEST));

    BaseECardSignatureValidator.fillIn(report, null, "some result message");

    assertThat(report.getOverallResult()
                     .getResultMajor()).isEqualTo(ValidationResultMajor.INDETERMINED.toString());
    assertThat(report.getOverallResult().getResultMinor()).isEqualTo(ECardResultMinor.PARAMETER_ERROR);
    assertThat(report.getOverallResult().getResultMessage().getValue()).isEqualTo("some result message");
    assertThat(report.getVr()).isNull();
  }

  /**
   * Asserts that report is filled with invalid result code.
   */
  @Test
  public void fillInInvalid()
  {
    var response = new ResponseBaseType();
    var optionalOutputs = new AnyType();
    var verificationReportType = FACTORY_OASIS_VR.createVerificationReportType();
    var individualReport = new IndividualReportType();
    var individualReportResult = new Result();
    individualReportResult.setResultMinor(ECardResultMinor.INVALID_SIGNATURE);
    individualReport.setResult(individualReportResult);
    verificationReportType.getIndividualReport().add(individualReport);
    JAXBElement<VerificationReportType> element = FACTORY_OASIS_VR.createVerificationReport(verificationReportType);
    optionalOutputs.getAny().add(element);
    response.setOptionalOutputs(optionalOutputs);
    var result = new Result();
    result.setResultMajor(ECardResultMajor.ERROR);
    response.setResult(result);
    var report = new SignatureReportPart(new Reference(TEST));

    BaseECardSignatureValidator.fillIn(report, response, null);

    assertThat(report.getOverallResult()
                     .getResultMajor()).isEqualTo(ValidationResultMajor.INVALID.toString());
    assertThat(report.getOverallResult().getResultMinor()).isEqualTo(ECardResultMinor.INVALID_SIGNATURE);
    assertThat(report.getVr()).isEqualTo(verificationReportType);
  }

  /**
   * Asserts that report is filled with valid result code.
   */
  @Test
  public void fillInValid()
  {
    var response = new ResponseBaseType();
    var optionalOutputs = new AnyType();
    var verificationReportType = FACTORY_OASIS_VR.createVerificationReportType();
    verificationReportType.getIndividualReport().add(new IndividualReportType());
    var element = FACTORY_OASIS_VR.createVerificationReport(verificationReportType);
    optionalOutputs.getAny().add(element);
    response.setOptionalOutputs(optionalOutputs);
    var result = new Result();
    result.setResultMajor(ValidationResultMajor.VALID.toString());
    response.setResult(result);
    var report = new SignatureReportPart(new Reference(TEST));

    BaseECardSignatureValidator.fillIn(report, response, null);

    assertThat(report.getOverallResult().getResultMajor()).isEqualTo(ValidationResultMajor.VALID.toString());
    assertThat(report.getOverallResult().getResultMessage()).isNull();
    assertThat(report.getVr()).isEqualTo(verificationReportType);
  }
}
