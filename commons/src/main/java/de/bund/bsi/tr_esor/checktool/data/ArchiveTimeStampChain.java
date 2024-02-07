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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;


/**
 * Parsed ArchiveTimeStampChain representation.
 *
 * @author MO
 */
public class ArchiveTimeStampChain extends ArrayList<ArchiveTimeStamp> implements ASN1Encodable
{

    private static final long serialVersionUID = -3432163732812450811L;

    /**
     * Constructs a new ArchiveTimeStampChain representation from its ASN&#46;1 notation.
     *
     * @param element ATS chain as parsed ASN.1
     * @throws IOException
     */
    public ArchiveTimeStampChain(ASN1Encodable element) throws IOException
    {
        super();

        if (element instanceof ASN1Sequence)
        {
            var chain = (ASN1Sequence)element;
            for (var ats : chain)
            {
                add(new ArchiveTimeStamp(ats));
            }
        }
        else
        {
            throw new IllegalArgumentException("Element is not an ASN1Sequence");
        }
    }

    /**
     * Returns the ASN&#46;1 encoded representation of this ATS chain.
     *
     * @throws IOException
     */
    public byte[] getEncoded() throws IOException
    {
        return toASN1Primitive().getEncoded();
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        var atsc = new ASN1EncodableVector();
        forEach(atsc::add);
        return new DERSequence(atsc);
    }
}
