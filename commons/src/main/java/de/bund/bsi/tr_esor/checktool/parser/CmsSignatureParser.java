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
import java.util.Arrays;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;


/**
 * Recognizes and parses CMS signed data.
 *
 * @author HMA, TT
 */
public class CmsSignatureParser implements Parser<CMSSignedData>
{

  private static final byte CONSTRUCTED_SEQUENCE = 0x30;

  private static final byte[] CMS_SIGNED_OBJECT_IDENTIFIER = new byte[]{0x06, // object identifier
                                                                        0x09, // length of our OID
                                                                        // OID value 1.2.840.113549.1.7.2:
                                                                        0x2a, (byte)0x86, 0x48, (byte)0x86,
                                                                        (byte)0xf7, 0x0d, 0x01, 0x07, 0x02};

  private static final int BUF_SIZE = CMS_SIGNED_OBJECT_IDENTIFIER.length + 5;

  private InputStream input;

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
    if (len < BUF_SIZE || buf[0] != CONSTRUCTED_SEQUENCE)
    {
      return false;
    }
    int numLenBytes = getNumLenBytes(buf[1]);
    byte[] foundOid = Arrays.copyOfRange(buf,
                                         1 + numLenBytes,
                                         1 + numLenBytes + CMS_SIGNED_OBJECT_IDENTIFIER.length);
    return Arrays.equals(foundOid, CMS_SIGNED_OBJECT_IDENTIFIER);
  }

  @Override
  public CMSSignedData parse() throws IOException
  {
    try
    {
      return new CMSSignedData(input);
    }
    catch (CMSException e)
    {
      throw new IOException("CMS invalid format", e);
    }
  }

  /**
   * Calculates the number of bytes which describe the content length of the constructed sequence. This is
   * needed to get the offset where the content of the sequence starts.
   * <p>
   * The highest bit is set to zero if the first byte is enough to determine the content length. If the
   * highest bit is set to one the other bits determine how many further bytes describe the content length.
   *
   * @param lengthByte the first byte of the length bytes of the constructed sequence
   */
  private int getNumLenBytes(byte lengthByte)
  {
    final int bit8Mask = 0b10000000;
    final int numberFollowingMask = 0b01111111;
    int numLenBytes = 1;
    if ((lengthByte & bit8Mask) > 0)
    {
      numLenBytes += lengthByte & numberFollowingMask;
    }
    return numLenBytes;
  }

}
