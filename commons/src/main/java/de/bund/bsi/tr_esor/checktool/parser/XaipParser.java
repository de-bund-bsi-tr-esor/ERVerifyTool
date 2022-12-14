/*-
 * Copyright (c) 2018
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

import java.io.IOException;
import java.util.Optional;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.dom.DOMSource;

import jakarta.xml.bind.JAXBException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3._2000._09.xmldsig_.CanonicalizationMethodType;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import de.bund.bsi.tr_esor.checktool.data.XaipAndSerializer;
import de.bund.bsi.tr_esor.checktool.xml.ComprehensiveXaipSerializer;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.xaip.XAIPType;


/**
 * Parses a XAIP and remembers the original DOM structure containing all the non-tag nodes, namespace prefixes
 * and so on. <strong>Warning:</strong> Instances are not thread-safe.
 *
 * @author TT, WS
 */
public class XaipParser extends RegexBasedParser<XaipAndSerializer>
{

  private static final Logger LOG = LoggerFactory.getLogger(XaipParser.class);

  private static final DocumentBuilderFactory DBF = newDocumentBuilderFactory();

  private final LXaipReader lXaipReader;

  private Document document;

  private String canonicalizationAlgo;

  /**
   * Creates new instance which may be re-used but is not thread safe.
   */
  public XaipParser(LXaipReader lXaipReader)
  {
    super(regexForMainTag("XAIP", "http://www.bsi.bund.de/tr-esor/xaip"));
    this.lXaipReader = lXaipReader;
  }

  @Override
  public XaipAndSerializer parse() throws IOException
  {
    try
    {
      DocumentBuilder db = DBF.newDocumentBuilder();
      document = db.parse(input);

      XAIPType result = XmlHelper.parse(new DOMSource(document),
                                        XAIPType.class,
                                        XmlHelper.FACTORY_XAIP.getClass().getPackage().getName() + ":"
                                                        + XmlHelper.FACTORY_ASIC.getClass()
                                                                                .getPackage()
                                                                                .getName());
      canonicalizationAlgo = Optional.ofNullable(result.getPackageHeader().getCanonicalizationMethod())
                                     .map(CanonicalizationMethodType::getAlgorithm)
                                     .orElse("http://www.w3.org/2001/10/xml-exc-c14n#");
      return new XaipAndSerializer(result, createSerializer());
    }
    catch (JAXBException | ParserConfigurationException | SAXException e)
    {
      LOG.error("problem parsing the XAIP XML", e);
      throw new IOException("Invalid XML", e);
    }
  }

  /**
   * Returns a serializer which preserves document context and name space prefixes of the last parsed XAIP.
   */
  public ComprehensiveXaipSerializer createSerializer()
  {
    return new ComprehensiveXaipSerializer(document, canonicalizationAlgo, lXaipReader);
  }

  /**
   * Creates a new instance of a DocumentBuilderFactory avoiding several types of security leaks.
   */
  private static DocumentBuilderFactory newDocumentBuilderFactory()
  {
    DocumentBuilderFactory inst = DocumentBuilderFactory.newInstance();
    inst.setNamespaceAware(true);
    try
    {
      inst.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
      inst.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      inst.setFeature("http://xml.org/sax/features/external-general-entities", false);
      inst.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      inst.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    }
    catch (ParserConfigurationException e)
    {
      throw new IllegalArgumentException("Implementation does not support setting safe parameters!", e);
    }
    inst.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    inst.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    inst.setXIncludeAware(false);
    inst.setExpandEntityReferences(false);
    return inst;
  }
}
