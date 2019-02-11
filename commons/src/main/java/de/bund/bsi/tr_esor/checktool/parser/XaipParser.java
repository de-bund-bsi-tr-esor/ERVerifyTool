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

import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.transform.stream.StreamSource;

import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.xaip._1.XAIPType;


/**
 * Parses a XAIPType out of a binary content or a DOM element.
 *
 * @author TT
 */
public class XaipParser extends RegexBasedParser<XAIPType>
{

  /**
   * Creates new instance.
   */
  public XaipParser()
  {
    super(regexForMainTag("XAIP", "http://www.bsi.bund.de/tr-esor/xaip/1.2"));
  }

  @Override
  public XAIPType parse() throws IOException
  {
    try
    {
      return XmlHelper.parse(new StreamSource(input),
                             XAIPType.class,
                             XmlHelper.FACTORY_XAIP.getClass().getPackage().getName());
    }
    catch (JAXBException e)
    {
      throw new IOException("invalid xml", e);
    }
  }
}
