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
import java.util.Arrays;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;



/**
 * Class to parse and analyze encryption info.
 *
 * @author TT
 */
public class EncryptionInfo implements ASN1Encodable
{

  /** OID of information. */
  private final ASN1ObjectIdentifier oid;

  /** Value of information. */
  private final byte[] value;

  /**
   * Constructor (generate and initialize object).
   *
   * @param id OID of information
   * @param val value of information
   */
  public EncryptionInfo(String id, byte[] val)
  {
    Objects.requireNonNull(val, "value may not be null");

    oid = new ASN1ObjectIdentifier(id);
    value = Arrays.copyOf(val, val.length);
  }

  /**
   * Constructor (generated from input parameter).
   *
   * @param obj ASN.1 object
   * @throws IOException
   */
  public EncryptionInfo(ASN1Object obj) throws IOException
  {
    if (!(obj instanceof ASN1Sequence) || ((ASN1Sequence)obj).size() != 2)
    {
      throw new IOException("not valid (EI-1)");
    }
    ASN1Sequence s = (ASN1Sequence)obj;
    oid = ASN1ObjectIdentifier.getInstance(s.getObjectAt(0));
    value = s.getObjectAt(1).toASN1Primitive().getEncoded(ASN1Encoding.DER);
  }

  @Override
  public ASN1Primitive toASN1Primitive()
  {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(oid);
    v.add(new DEROctetString(value));
    return new DERSequence(v);
  }
}
