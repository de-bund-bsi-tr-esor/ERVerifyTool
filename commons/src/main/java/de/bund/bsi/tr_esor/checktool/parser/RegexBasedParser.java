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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;


/**
 * Base class for parsers which use regular expressions to determine whether input is suitable.
 *
 * @author TT
 * @param <T> type of parsed object
 */
public abstract class RegexBasedParser<T> implements Parser<T>
{

  /**
   * Data to parse.
   */
  protected InputStream input;

  private final Pattern pattern;

  private static final int BUF_SIZE = 2 * 1024;

  /**
   * Creates new instance.
   *
   * @param regex matches beginning of input if input is feasible
   */
  protected RegexBasedParser(String regex)
  {
    pattern = Pattern.compile(regex);
  }

  @Override
  public void setInput(InputStream input)
  {
    this.input = input;
    if (!input.markSupported())
    {
      throw new IllegalArgumentException("can only handle streams which support mark/reset");
    }
  }

  @Override
  public boolean canParse() throws IOException
  {
    input.mark(BUF_SIZE);
    byte[] buf = new byte[BUF_SIZE];
    int len = input.read(buf, 0, BUF_SIZE);
    input.reset();
    String beginning = new String(buf, 0, len, StandardCharsets.UTF_8);
    return pattern.matcher(beginning).find();
  }

  /**
   * Returns a regular expression which matches XML files with specified root tag.
   *
   * @param localName
   * @param namespaceURI required (root tags without namespace not supported here)
   */
  protected static String regexForMainTag(String localName, String namespaceURI)
  {
    return "\\A(<\\?xml [^>]*>[^<]*)?(<([a-zA-Z]\\w*):" + localName + " [^>]*xmlns:\\3=\"" + namespaceURI
           + "\")|(<" + localName + " [^>]*xmlns=\"" + namespaceURI + "\")";
  }
}
