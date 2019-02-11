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
package de.bund.bsi.tr_esor.checktool.conf;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Scanner;

import javax.xml.bind.UnmarshalException;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.xml.sax.SAXException;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.entry.IsValidXML;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.Validator;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;


/**
 * Unit tests for accessing configuration values.
 *
 * @author TT
 */
public class TestConfigurator
{

  private static String xml;

  /**
   * How JUnit checks exceptions.
   */
  @Rule
  public ExpectedException expected = ExpectedException.none();

  /**
   * Provides some configuration data.
   *
   * @throws Exception
   */
  @BeforeClass
  public static void setUpClass() throws Exception
  {
    xml = readFile("/configForTestingFactory.xml");
  }

  /**
   * Reset configuration to continue normal testing.
   *
   * @throws Exception
   */
  @AfterClass
  public static void tearDownClass() throws Exception
  {
    TestUtils.loadDefaultConfig();
  }

  /**
   * Asserts that the example configuration file is valid by its schema.
   *
   * @throws SAXException
   */
  @Test
  public void exampleConfig() throws Exception
  {
    URL schema = IsValidXML.class.getResource("/Config.xsd");
    for ( String path : new String[]{"/config.xml", "/configForTestingFactory.xml", "/release/config.xml"} )
    {
      assertThat(path, readFile(path), new IsValidXML("configuration", schema));
    }
  }

  /**
   * Asserts that load method throws Exception if configuration cannot be parsed.
   *
   * @throws Exception
   */
  @Test
  public void wrongInput() throws Exception
  {
    Configurator systemUnderTest = Configurator.getInstance();
    try (InputStream ins = TestConfigurator.class.getResourceAsStream("/xaip/xaip_ok_ers.xml"))
    {
      expected.expect(UnmarshalException.class);
      systemUnderTest.load(ins);
    }
  }

  /**
   * Asserts that the configured validator information can be returned.
   *
   * @throws Exception
   */
  @Test
  public void getValidator() throws Exception
  {
    Configurator systemUnderTest = getSystemUnderTestFor("");
    Validator<?, ?, ?> val = (Validator<?, ?, ?>)systemUnderTest.getValidators()
                                                                .get(EvidenceRecord.class,
                                                                     ErValidationContext.class,
                                                                     ReportPart.class,
                                                                     "test_profile")
                                                                .get();
    assertThat(val.getClass().getName(),
               is("de.bund.bsi.tr_esor.checktool.validation.TestValidatorFactory$OtherErValidator"));
  }

  /**
   * Asserts that a misconfigured validator class is detected.
   */
  @Test
  public void notAValidator() throws Exception
  {
    checkWrongValidator(HashMap.class.getName(),
                        EvidenceRecord.class.getName(),
                        "",
                        "Configured class does not extend Validator: java.util.HashMap");
  }

  /**
   * Asserts that a misconfigured validator class is detected.
   */
  @Test
  public void wrongTargetClass() throws Exception
  {
    checkWrongValidator("de.bund.bsi.tr_esor.checktool.validation.TestValidatorFactory$OtherErValidator",
                        String.class.getName(),
                        "",
                        "Validator de.bund.bsi.tr_esor.checktool.validation.TestValidatorFactory$OtherErValidator does not comply with target class: java.lang.String");
  }

  /**
   * Asserts that a misconfigured validator class is detected.
   */
  @Test
  public void wrongConstructionParameters() throws Exception
  {
    checkWrongValidator("de.bund.bsi.tr_esor.checktool.validation.TestValidatorFactory$OtherErValidator",
                        EvidenceRecord.class.getName(),
                        "<parameter name=\"dummy\">ignored</parameter>",
                        "Missing constructor with Map parameter in class:");
  }

  private void checkWrongValidator(String valClazz, String targetClazz, String params, String expectedMessage)
    throws Exception
  {
    String valTag = "<Validator><className>" + valClazz + "</className>" + params + "<targetType>"
                    + targetClazz + "</targetType></Validator>";
    expected.expect(ReflectiveOperationException.class);
    expected.expectMessage(expectedMessage);
    getSystemUnderTestFor(valTag);
  }

  private static String readFile(String path) throws IOException
  {
    try (InputStream ins = TestConfigurator.class.getResourceAsStream(path);
      Scanner scan = new Scanner(ins, "utf-8"))
    {
      return scan.useDelimiter("\\A").next();
    }
  }

  private Configurator getSystemUnderTestFor(String configPart) throws Exception
  {
    Configurator systemUnderTest = Configurator.getInstance();
    String currentXml = xml.replace("<ConfiguredObjects />",
                                    "<ConfiguredObjects>" + configPart + "</ConfiguredObjects>");
    try (ByteArrayInputStream bis = new ByteArrayInputStream(currentXml.getBytes(StandardCharsets.UTF_8)))
    {
      systemUnderTest.load(bis);
    }
    return systemUnderTest;
  }
}
