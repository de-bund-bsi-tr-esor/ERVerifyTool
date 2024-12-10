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
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.Attribute;


/**
 * Class to parse and analyze CryptoInfos attributes from ER.
 *
 * @author TT
 */
public class CryptoInfo implements ASN1Encodable
{

    /** List of attributes of the crypto info. */
    private final List<Attribute> attributes = new ArrayList<>();

    /**
     * Constructor (generated from input parameter).
     *
     * @param obj ASN.1 object
     * @throws IOException
     */
    public CryptoInfo(ASN1Object obj) throws IOException
    {
        if (!(obj instanceof ASN1Sequence))
        {
            throw new IOException("Element is not an ASN1Sequence");
        }
        var s = (ASN1Sequence)obj;
        if (s.size() == 0)
        {
            throw new IOException("ASN1Sequence is empty");
        }
        for (var i = 0; i < s.size(); i++)
        {
            var e = s.getObjectAt(i);
            if (!(e instanceof ASN1Sequence) && !(e instanceof Attribute))
            {
                throw new IOException("Element is not an Attribute");
            }
            attributes.add(Attribute.getInstance(e));
        }
    }

    /**
     * Returns the attribute with given index.
     *
     * @param idx index of attribute
     */
    public Attribute getAttribute(int idx)
    {
        return idx < attributes.size() ? attributes.get(idx) : null;
    }

    /**
     * Returns the attributes list
     */
    public List<Attribute> getAttributes()
    {
        return attributes;
    }

    /**
     * Gets the number of attributes in list.
     *
     * @return number of attributes
     */
    public int numberOfAttributes()
    {
        return attributes.size();
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        var attrs = new ASN1EncodableVector();
        attributes.forEach(attrs::add);
        return new DERSequence(attrs);
    }

}
