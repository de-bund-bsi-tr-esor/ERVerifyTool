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
package de.bund.bsi.tr_esor.checktool.parser;

import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

import org.junit.Test;
import org.xml.sax.SAXException;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.entry.IsValidXML;
import de.bund.bsi.tr_esor.checktool.validation.ParserFactory;
import de.bund.bsi.tr_esor.xaip._1.EvidenceRecordType;
import de.bund.bsi.tr_esor.xaip._1.XAIPType;


/**
 * Unit tests for parsers.
 *
 * @author TT
 */
public class TestParsers
{

  /**
   * Makes sure our test EvidenceRecordType file satisfies the XML schema.
   *
   * @throws IOException
   * @throws SAXException
   */
  @Test
  public void exampleErFile() throws IOException, SAXException
  {
    try (InputStream ins = TestParsers.class.getResourceAsStream("/bin/example.er.xml");
      Scanner scan = new Scanner(ins, "UTF-8"))
    {
      String xml = scan.useDelimiter("\\A").next();
      assertThat(xml,
                 new IsValidXML("EvidenceRecordType",
                                TestParsers.class.getResource("/tr-esor-xaip-v1_2.xsd")));
    }
  }

  /**
   * Asserts that the ParserFactory is able to return the expected number of built-in parsers.
   *
   * @throws Exception
   */
  @SuppressWarnings("boxing")
  @Test
  public void testFactoryBuiltInParsers() throws Exception
  {
    TestUtils.loadDefaultConfig();
    int count = 0;
    for ( Parser<?> parser : ParserFactory.getInstance().getAvailableParsers("unknown") )
    {
      assertNotNull(parser);
      count++;
    }
    assertThat("count", count, is(5));
  }

  /**
   * Checks methods of XaipParser.
   *
   * @throws IOException
   */
  @Test
  public void testXaipParser() throws IOException
  {
    genericChecks(new XaipParser(), "/xaip/xaip_ok_ers.xml", XAIPType.class);
  }

  /**
   * Checks methods of EvidenceRecordTypeParser.
   *
   * @throws IOException
   */
  @Test
  public void testEvidenceRecordTypeParser() throws IOException
  {
    genericChecks(new EvidenceRecordTypeParser(), "/bin/example.er.xml", EvidenceRecordType.class);
  }

  /**
   * Parses an ASN&#46;1 evidence record.
   *
   * @throws IOException
   */
  @Test
  public void testAsn1ErParser() throws IOException
  {
    for ( String path : new String[]{"/bin/example.ers.b64", "/bin/ATS1_BIN_ER.ers.b64"} )
    {
      try (InputStream ins = getBinaryStream(path))
      {
        Parser<?> parser = new ASN1EvidenceRecordParser();
        parser.setInput(ins);
        assertTrue("can parse correct input " + path, parser.canParse());
        assertThat("parsed " + path, parser.parse(), instanceOf(EvidenceRecord.class));
      }
    }

    try (InputStream ins = new ByteArrayInputStream(new byte[0]))
    {
      Parser<?> parser = new ASN1EvidenceRecordParser();
      parser.setInput(ins);
      assertFalse("cannot parse empty input", parser.canParse());
    }
  }

  /**
   * Assert that the {@link CmsSignatureParser} recognizes which files it can parse.
   *
   * @throws Exception
   */
  @Test
  public void canParseCms() throws Exception
  {
    CmsSignatureParser parser = new CmsSignatureParser();
    try (InputStream ins = getBinaryStream("/cms/encapsulated_with_er.p7s.b64"))
    {
      parser.setInput(ins);
      assertTrue(parser.canParse());
    }
    try (InputStream ins = getBinaryStream("/bin/example.ers.b64"))
    {
      parser.setInput(ins);
      assertFalse(parser.canParse());
    }
  }

  private InputStream getBinaryStream(String path)
  {
    return new ByteArrayInputStream(TestUtils.decodeTestResource(path));
  }

  /**
   * Asserts that the parser reports wrong input and that parsing creates object of expected type after input
   * was reported suitable.
   *
   * @param parser
   * @param inputPath
   * @param expectedClass
   * @return parsed object
   * @throws IOException
   */
  private <T> T genericChecks(Parser<T> parser, String inputPath, Class<T> expectedClass) throws IOException
  {
    String wrong = "<ns:Comment xmlns:ns=\"urn:unknown\">This is certainly not the expected Input</ns:Comment>";
    try (InputStream ins = new ByteArrayInputStream(wrong.getBytes(StandardCharsets.UTF_8)))
    {
      parser.setInput(ins);
      assertFalse("can parse wrong input", parser.canParse());
    }
    try (InputStream ins = TestParsers.class.getResourceAsStream(inputPath))
    {
      parser.setInput(ins);
      assertTrue("can parse correct input", parser.canParse());
      assertTrue("can parse correct input (second try)", parser.canParse());
      T result = parser.parse();
      assertThat("parsed", result, instanceOf(expectedClass));
      return result;
    }
  }
}
