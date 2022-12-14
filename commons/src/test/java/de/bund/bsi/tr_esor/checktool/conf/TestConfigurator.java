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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Scanner;

import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.UnmarshalException;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

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
@SuppressWarnings({"PMD.CommentRequired", "checkstyle:JavadocMethod"})
public class TestConfigurator
{

  @Rule
  public ExpectedException expected = ExpectedException.none();

  private Configurator sut;

  @Before
  public void setUp()
  {
    sut = new Configurator();
  }

  /**
   * Asserts that the example configuration file is valid by its schema.
   */
  @Test
  public void exampleConfig() throws Exception
  {
    var schema = IsValidXML.class.getResource("/Config.xsd");
    for ( var path : new String[]{"/config.xml", "/configForTestingFactory.xml", "/release/config.xml"} )
    {
      assertThat(path, readFile(path), new IsValidXML("configuration", schema));
    }
  }

  /**
   * Asserts that load method throws Exception if configuration cannot be parsed.
   */
  @Test
  public void wrongInput() throws Exception
  {
    try (var ins = TestConfigurator.class.getResourceAsStream("/xaip/xaip_ok_ers.xml"))
    {
      expected.expect(UnmarshalException.class);
      sut.load(ins);
    }
  }

  /**
   * Asserts that the configured validator information can be returned.
   */
  @Test
  public void canGetValidator() throws Exception
  {
    load(sut, readFile("/configForTestingFactory.xml"));

    var val = (Validator<?, ?, ?>)sut.getValidators()
                                     .get(EvidenceRecord.class,
                                          ErValidationContext.class,
                                          ReportPart.class,
                                          "test_profile")
                                     .get();
    assertThat(val.getClass().getName(),
               is("de.bund.bsi.tr_esor.checktool.validation.TestValidatorFactory$OtherErValidator"));
  }

  @Test
  public void lXaipDataDirectoryHasDefault() throws Exception
  {
    load(sut, readFile("/configForTestingFactory.xml"));

    assertThat(sut.getLXaipDataDirectory(ProfileNames.RFC4998), equalTo(Path.of(".")));
  }

  @Test
  public void lXaipDataDirectoryHasDefaultForProfile() throws Exception
  {
    load(sut, readFile("/configForTestingFactory.xml"));

    assertThat(sut.getLXaipDataDirectory("test_profile"), equalTo(Path.of(".")));
  }

  @Test
  public void failsHasVerificationServiceNoProfileFound() throws Exception
  {
    load(sut, readFile("/configForTestingFactory.xml"));

    var result = sut.hasVerificationService("notExisting");

    assertThat(result, is(false));
  }

  @Test
  public void failsHasVerificationServiceProfileWithoutVerificationService() throws Exception
  {
    load(sut, readFile("/configForTestingFactory.xml"));

    var result = sut.hasVerificationService("test_profile");

    assertThat(result, is(false));
  }

  @Test
  public void passesHasVerificationService() throws Exception
  {
    load(sut, readFile("/config.xml"));

    var result = sut.hasVerificationService("TR-ESOR");

    assertThat(result, is(true));
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
    var valTag = "<Validator><className>" + valClazz + "</className>" + params + "<targetType>" + targetClazz
                 + "</targetType></Validator>";
    var xml = readFile("/configForTestingFactory.xml").replace("<ConfiguredObjects />",
                                                               "<ConfiguredObjects>" + valTag
                                                                                        + "</ConfiguredObjects>");

    expected.expect(ReflectiveOperationException.class);
    expected.expectMessage(expectedMessage);

    load(sut, xml);
  }

  private static String readFile(String path) throws IOException
  {
    try (var ins = TestConfigurator.class.getResourceAsStream(path);
      var scan = new Scanner(ins, StandardCharsets.UTF_8))
    {
      return scan.useDelimiter("\\A").next();
    }
  }

  private static void load(Configurator sut, String file)
    throws IOException, JAXBException, ReflectiveOperationException
  {
    try (var bis = new ByteArrayInputStream(file.getBytes(StandardCharsets.UTF_8)))
    {
      sut.load(bis);
    }
  }
}
