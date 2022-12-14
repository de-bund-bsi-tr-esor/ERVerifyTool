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
package de.bund.bsi.tr_esor.checktool.data;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;


/**
 * Represents a single node within a reduced hash tree which is a set of digest values. By definition this
 * must be called tree, but it has no tree structure. Note that the contained hashes are not ordered.
 *
 * @author TT
 */
public class PartialHashtree extends ArrayList<byte[]> implements ASN1Encodable
{

  private static final long serialVersionUID = 1L;

  /**
   * constructor (generated from input parameter)
   *
   * @param obj ASN.1 object
   * @throws IOException
   */
  public PartialHashtree(ASN1Object obj) throws IOException
  {
    super();

    if (!(obj instanceof ASN1Sequence))
    {
      throw new IOException("not valid (PH-1)");
    }
    var s = (ASN1Sequence)obj;
    for ( var i = 0 ; i < s.size() ; i++ )
    {
      var e = s.getObjectAt(i);
      if (!(e instanceof ASN1OctetString))
      {
        throw new IOException("not valid (PH-2)");
      }
      var o = (ASN1OctetString)e;
      add(o.getOctets());
    }
  }

  /**
   * Same as super&#46;contains but uses Arrays&#46;equals.
   */
  public boolean contains(byte[] digestValue)
  {
    return stream().anyMatch(value -> Arrays.equals(value, digestValue));
  }

  @Override
  public ASN1Primitive toASN1Primitive()
  {
    var pht = new ASN1EncodableVector();
    stream().map(DEROctetString::new).forEach(pht::add);
    return new DERSequence(pht);
  }
}
