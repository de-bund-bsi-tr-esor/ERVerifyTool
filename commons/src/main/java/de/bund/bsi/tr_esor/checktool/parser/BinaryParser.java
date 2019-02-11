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


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;



/**
 * Just a place holder for treating input as binary document of unknown type. Do not use before all more
 * special appropriate formats have been tried!
 *
 * @author TT
 */
public class BinaryParser implements Parser<byte[]>
{

  private InputStream input;

  @Override
  public void setInput(InputStream input)
  {
    this.input = input;
  }

  @Override
  public boolean canParse() throws IOException
  {
    return true;
  }

  @Override
  public byte[] parse() throws IOException
  {
    return readAll(input);
  }

  /**
   * Reads complete content of a stream and returns it as byte array. We do not want dependency to another
   * library for this one method
   */
  public static byte[] readAll(InputStream ins) throws IOException
  {
    byte[] buf = new byte[4 * 1024];
    int nRead = 0;
    try (ByteArrayOutputStream out = new ByteArrayOutputStream())
    {
      while ((nRead = ins.read(buf)) != -1)
      {
        out.write(buf, 0, nRead);
      }
      return out.toByteArray();
    }
  }
}
