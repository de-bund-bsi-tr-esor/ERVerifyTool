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

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;
import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;


/**
 * Matcher which ensures schema conformity of an XML text. Matcher handles Strings to make test report look
 * better.
 *
 * @author TT
 */
public class IsValidXML extends TypeSafeMatcher<String> implements ErrorHandler
{

  @SuppressWarnings("PMD.FieldNamingConventions")
  private static final Map<String, IsValidXML> matcherCache = new HashMap<>();

  private final String schemaName;

  private Schema schema;

  private SAXParseException exForItem = null;

  /**
   * Specify the schema to be used at construction time.
   *
   * @param schemaName name of the schema to mention in the error message
   * @param url Location of the schema to check against, optional. If <code>null</code> then any well-formed
   *          XML will pass.
   * @throws SAXException in case schema cannot be parsed
   */
  public IsValidXML(String schemaName, URL url) throws SAXException
  {
    super();
    if (url == null)
    {
      this.schemaName = "undefined";
    }
    else
    {
      this.schemaName = schemaName;
      var sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
      schema = sf.newSchema(url);
    }
  }

  private static IsValidXML getMatcher(String name, String url) throws SAXException
  {
    var result = matcherCache.get(name);
    if (result == null)
    {
      result = new IsValidXML(name, IsValidXML.class.getResource(url));
      matcherCache.put(name, result);
    }
    return result;
  }

  /**
   * Returns a matcher which checks the given input against Verification Report schema.
   *
   * @throws SAXException
   */
  public static TypeSafeMatcher<String> matcherForValidVerificationReport() throws SAXException
  {
    return getMatcher("Verification Report", "/oasis-dssx-1.0-profiles-verification-report-cs1.xsd");
  }

  /**
   * Returns a matcher which checks the given input against TR Verification Report detail schema.
   *
   * @throws SAXException
   */
  public static TypeSafeMatcher<String> matcherForValidVerificationReportDetail() throws SAXException
  {
    return getMatcher("Verification Report Detail", "/tr-esor-verification-report-V1.3.xsd");
  }

  /**
   * Returns <code>true</code> if item satisfies SOAP schema.
   */
  @Override
  public boolean matchesSafely(String item)
  {
    try
    {
      var ins = new ByteArrayInputStream(item.getBytes(StandardCharsets.UTF_8));
      var dbf = DocumentBuilderFactory.newInstance();
      dbf.setNamespaceAware(true);
      if (schema != null)
      {
        dbf.setSchema(schema);
      }
      var db = dbf.newDocumentBuilder();
      db.setErrorHandler(this);
      db.parse(ins);
      return true;
    }
    catch (SAXParseException e)
    {
      exForItem = e;
      return false;
    }
    catch (Exception e)
    {
      return false;
    }
  }

  @Override
  public void describeTo(Description description)
  {
    if (exForItem == null)
    {
      description.appendText("XML satisfying " + schemaName + " schema");
    }
    else
    {
      description.appendText("XML matching schema " + schemaName + ", but found problem in line "
                             + exForItem.getLineNumber() + ", col. " + exForItem.getColumnNumber() + ", "
                             + exForItem.getLocalizedMessage());
    }
  }

  @Override
  public void error(SAXParseException exception) throws SAXException
  {
    throw exception;
  }

  @Override
  public void fatalError(SAXParseException exception) throws SAXException
  {
    throw exception;
  }

  @Override
  public void warning(SAXParseException exception) throws SAXException
  {
    throw exception;
  }

}
