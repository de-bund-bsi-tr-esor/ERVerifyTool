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
package de.bund.bsi.tr_esor.checktool;

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.namespace.QName;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.entry.ReportDetailLevel;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import oasis.names.tc.dss._1_0.core.schema.VerifyRequest;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.EvidenceRecordValidityType.ArchiveTimeStampSequence;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;


/**
 * Collection of common test utility methods.
 *
 * @author MO
 */
public final class TestUtils
{

  private TestUtils()
  {
    // Utility class
  }

  /**
   * Returns a ReturnVerificationReport with ALL_DETAILS as ReportDetailLevel.
   */
  public static ReturnVerificationReport createReturnVerificationReport()
  {
    return createReturnVerificationReport(null);
  }

  /**
   * Returns a ReturnVerificationReport with the given ReportDetailLevel. If no reportDetailLevel is
   * specified, the ALL_DETAILS ReportDetailLevel will be used.
   *
   * @param reportDetailLevel
   */
  public static ReturnVerificationReport createReturnVerificationReport(ReportDetailLevel reportDetailLevel)
  {
    ReturnVerificationReport result = FACTORY_OASIS_VR.createReturnVerificationReport();
    result.setReportDetailLevel(reportDetailLevel == null ? ReportDetailLevel.ALL_DETAILS.toString()
      : reportDetailLevel.toString());
    return result;

  }

  /**
   * Reads the given test resource and decodes it (assuming it is base64 encoded).
   *
   * @param testResource
   */
  public static byte[] decodeTestResource(String testResource)
  {
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
      InputStream erStream = TestUtils.class.getResourceAsStream(testResource))
    {
      byte[] buf = new byte[1024];
      int readbytes;
      while ((readbytes = erStream.read(buf)) != -1)
      {
        baos.write(buf, 0, readbytes);
      }
      return Base64.getDecoder()
                   .decode(new String(baos.toByteArray(), StandardCharsets.UTF_8).replace("\n", ""));
    }
    catch (IOException e)
    {
      fail("problem decoding " + testResource + ": " + e);
      return null;
    }
  }

  /**
   * Returns XML representation of marshalled data.
   *
   * @param data
   * @param contextPath
   * @throws JAXBException
   * @throws IOException
   */
  public static String toString(Object data, String contextPath) throws JAXBException, IOException
  {
    JAXBContext ctx = JAXBContext.newInstance(contextPath);
    Marshaller m = ctx.createMarshaller();
    try (ByteArrayOutputStream outs = new ByteArrayOutputStream())
    {
      m.marshal(data, outs);
      return new String(outs.toByteArray(), StandardCharsets.UTF_8);
    }
  }

  /**
   * Just for development.
   *
   * @param request
   * @throws JAXBException
   * @throws IOException
   */
  public static void dumpXml(VerifyRequest request) throws JAXBException, IOException
  {
    System.out.println(TestUtils.toString(request, XmlHelper.FACTORY_DSS.getClass().getPackage().getName()));
  }

  /**
   * Just for development.
   *
   * @param atss
   * @throws JAXBException
   * @throws IOException
   */
  public static void dumpXml(ArchiveTimeStampSequence atss) throws JAXBException, IOException
  {
    System.out.println(TestUtils.toString(new JAXBElement<>(new QName("ATSS"), ArchiveTimeStampSequence.class,
                                                            atss),
                                          XmlHelper.FACTORY_OASIS_VR.getClass().getPackage().getName()));
  }

  /**
   * Loads configuration specified by given resource path.
   *
   * @param resourcePath
   * @throws Exception
   */
  public static void loadConfig(String resourcePath) throws Exception
  {
    try (InputStream ins = TestUtils.class.getResourceAsStream(resourcePath))
    {
      Configurator.getInstance().load(ins);
    }
  }

  /**
   * Loads default configuration for testing.
   *
   * @throws Exception
   */
  public static void loadDefaultConfig() throws Exception
  {
    loadConfig("/config.xml");
  }

}
