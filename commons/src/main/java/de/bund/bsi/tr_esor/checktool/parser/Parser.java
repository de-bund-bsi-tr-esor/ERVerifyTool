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


/**
 * Interface for parsers.
 *
 * @author HMA, TT
 * @param <T> type of parsed object
 */
public interface Parser<T>
{

  /**
   * Specifies input to parse.
   *
   * @param input must support mark/reset
   */
  void setInput(InputStream input);

  /**
   * Returns <code>true</code> if this parser can parse the given input. Input will always be reset.
   *
   * @throws IOException
   */
  boolean canParse() throws IOException;

  /**
   * Parses the input and returns the parsed object. If successful, the input stream is not reset!
   */
  T parse() throws IOException;


}
