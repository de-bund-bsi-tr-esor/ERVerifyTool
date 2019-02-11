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
package de.bund.bsi.tr_esor.checktool.xml;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.util.JAXBSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3._2000._09.xmldsig_.SignatureValueType;
import org.w3c.dom.Element;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.entry.ReportDetailLevel;
import de.bund.bsi.tr_esor.checktool.validation.report.EvidenceRecordReport;
import de.bund.bsi.tr_esor.checktool.validation.report.OutputCreator;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss._1_0.core.schema.VerificationTimeInfoType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IdentifierType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ObjectFactory;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.SignedObjectIdentifierType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationResultType;
import oasis.names.tc.saml._2_0.assertion.NameIDType;


/**
 * Collects the validation results into an XML verification report according to schema
 * "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#".
 *
 * @author BVO, HMA, KK, TT
 */
public final class VRCreator
{

  private static final Logger LOG = LoggerFactory.getLogger(VRCreator.class);

  private static Schema schema;

  static
  {
    try
    {
      schema = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
                            .newSchema(VRCreator.class.getResource("/oasis-dssx-1.0-profiles-verification-report-cs1.xsd"));
    }
    catch (SAXException e)
    {
      LOG.error("Failed to load schema", e);
    }
  }

  private VRCreator()
  {
    // static only
  }

  /**
   * Returns a verification report as defined in
   * "urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#".
   *
   * @param individualReports
   */
  public static VerificationReportType createReport(List<ReportPart> individualReports,
                                                    ReturnVerificationReport returnVerificationReport)
  {
    VerificationReportType report = XmlHelper.FACTORY_OASIS_VR.createVerificationReportType();
    VerificationTimeInfoType time = XmlHelper.FACTORY_DSS.createVerificationTimeInfoType();
    time.setVerificationTime(XmlHelper.getXMLGregorianCalendar(new Date()));
    report.setVerificationTimeInfo(time);

    IdentifierType id = XmlHelper.FACTORY_OASIS_VR.createIdentifierType();
    NameIDType value = new NameIDType();
    value.setValue(Configurator.getInstance().getVerifierID());
    id.setSAMLv2Identifier(value);
    report.setVerifierIdentity(id);

    individualReports.stream()
                     .map(r -> toIndividualReport(r, returnVerificationReport))
                     .forEach(report.getIndividualReport()::add);
    validateXml(report);
    return report;
  }

  /**
   * Validates report against schema as demanded by TR-ESOR-ERS-FEIN, p&#46; 29.
   *
   * @param report
   */
  private static void validateXml(VerificationReportType report)
  {
    try
    {
      Validator validator = schema.newValidator();
      validator.setErrorHandler(new LoggingErrorHandler(LOG));
      ObjectFactory factory = XmlHelper.FACTORY_OASIS_VR;
      JAXBContext context = JAXBContext.newInstance(factory.getClass().getPackage().getName());
      validator.validate(new JAXBSource(context, factory.createVerificationReport(report)));
    }
    catch (SAXException | JAXBException | IOException e)
    {
      LOG.error("Failed to validate report", e);
    }
  }

  /**
   * Creates XML representation of report.
   *
   * @param report whatever the validator created
   * @param targetClass required class within XML verification report
   */
  @SuppressWarnings("unchecked")
  public static <T> T translate(Object report, Class<T> targetClass)
  {
    if (targetClass.isInstance(report))
    {
      return targetClass.cast(report);
    }
    if (report instanceof OutputCreator
        && targetClass.isAssignableFrom(((OutputCreator<?>)report).getTargetClass()))
    {
      return ((OutputCreator<T>)report).getFormatted();
    }
    if (report instanceof Reference && targetClass == SignedObjectIdentifierType.class)
    {
      return (T)createIdentifier((Reference)report);
    }
    if (report instanceof ReportPart && !((ReportPart)report).isDetailsPresent())
    {
      return (T)createResultOnly((ReportPart)report);
    }
    return null;
  }

  private static IndividualReportType toIndividualReport(ReportPart report, ReturnVerificationReport returnVR)
  {
    if (report instanceof EvidenceRecordReport)
    {
      return createIndividualReport((EvidenceRecordReport)report, returnVR);
    }
    return translate(report, IndividualReportType.class);
  }

  private static IndividualReportType createResultOnly(ReportPart report)
  {
    IndividualReportType result = XmlHelper.FACTORY_OASIS_VR.createIndividualReportType();
    result.setSignedObjectIdentifier(createIdentifier(report.getReference()));
    result.setResult(translateResult(report.getOverallResultVerbose()));
    return result;
  }

  private static SignedObjectIdentifierType createIdentifier(Reference ref)
  {
    SignedObjectIdentifierType identifier = XmlHelper.FACTORY_OASIS_VR.createSignedObjectIdentifierType();
    if (ref.getSignatureValue() != null) // NOPMD searching the one nun-null value
    {
      SignatureValueType value = XmlHelper.FACTORY_DSIG.createSignatureValueType();
      value.setValue(ref.getSignatureValue());
      identifier.setSignatureValue(value);
    }
    else if (ref.getxPath() != null) // NOPMD
    {
      identifier.setXPath(ref.getxPath());
    }
    else
    {
      identifier.setFieldName(ref.toString());
    }
    return identifier;
  }

  private static IndividualReportType createIndividualReport(EvidenceRecordReport report,
                                                             ReturnVerificationReport returnVerificationReport)
  {
    IndividualReportType result = XmlHelper.FACTORY_OASIS_VR.createIndividualReportType();
    result.setSignedObjectIdentifier(createIdentifier(report.getReference()));
    result.setResult(translateResult(report.getOverallResultVerbose()));
    if (report.isDetailsPresent() && !specifiesNoDetails(returnVerificationReport))
    {
      result.setDetails(XmlHelper.FACTORY_DSS.createAnyType());
      try
      {
        Element element = XmlHelper.toElement(report.getFormatted(),
                                              XmlHelper.FACTORY_ESOR_VR.getClass().getPackage().getName(),
                                              XmlHelper.FACTORY_ESOR_VR::createEvidenceRecordReport);
        result.getDetails().getAny().add(element);
      }
      catch (JAXBException e)
      {
        LOG.error("Failed to process EvidenceRecordReport XML", e);
      }
    }
    return result;
  }

  private static boolean specifiesNoDetails(ReturnVerificationReport returnVR)
  {
    return ReportDetailLevel.NO_DETAILS.toString()
                                       .equals(Optional.ofNullable(returnVR)
                                                       .map(ReturnVerificationReport::getReportDetailLevel)
                                                       .orElse(""));
  }

  private static Result translateResult(VerificationResultType input)
  {
    Result result = XmlHelper.FACTORY_DSS.createResult();
    result.setResultMajor(input.getResultMajor());
    result.setResultMinor(input.getResultMinor());
    result.setResultMessage(input.getResultMessage());
    return result;
  }

  private static class LoggingErrorHandler implements ErrorHandler
  {

    private final Logger log;

    LoggingErrorHandler(Logger log)
    {
      this.log = log;
    }

    static final String MSG = "Schema violation in report detected";

    @Override
    public void warning(SAXParseException exception) throws SAXException
    {
      log.warn(MSG, exception);
    }

    @Override
    public void error(SAXParseException exception) throws SAXException
    {
      log.error(MSG, exception);
    }

    @Override
    public void fatalError(SAXParseException exception) throws SAXException
    {
      log.error(MSG, exception);
    }

  }
}
