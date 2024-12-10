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
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.function.BiConsumer;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Reader for relevant CAdES attributes from a CMS signature.
 *
 * @author HMA, TT
 */
public class CAdESReader
{

    private static final Logger LOG = LoggerFactory.getLogger(CAdESReader.class);

    private static final ASN1ObjectIdentifier ID_AA_ER_INTERNAL = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.49");

    private final AttributeTable attributeTable;

    /**
     * Creates new instance.
     *
     * @param signature
     */
    public CAdESReader(CMSSignedData signature)
    {
        var signerInfos = signature.getSignerInfos();
        var info = signerInfos.getSigners().iterator().next();
        attributeTable = info.getUnsignedAttributes();
    }

    /**
     * Returns <code>true</code> if signature has unsigned attributes at all.
     */
    public boolean hasUnsignedAttributes()
    {
        return attributeTable != null;
    }

    /**
     * Returns <code>true</code> if signature contains certificate values.
     */
    public boolean hasCertificateValues()
    {
        return attributeTable != null && attributeTable.get(PKCSObjectIdentifiers.id_aa_ets_certValues) != null;
    }

    /**
     * Returns <code>true</code> if signature contains revocation values.
     */
    public boolean hasRevocationValues()
    {
        return attributeTable != null && attributeTable.get(PKCSObjectIdentifiers.id_aa_ets_revocationValues) != null;
    }

    /**
     * Returns an embedded evidence record if any.
     */
    public byte[] getEmbeddedEvidenceRecord()
    {
        List<byte[]> parsedValues = getParsedValues(ID_AA_ER_INTERNAL, (o, r) -> r.add(getEncoded(o)));
        return parsedValues == null || parsedValues.isEmpty() ? null : parsedValues.get(0);
    }

    private byte[] getEncoded(Object o)
    {
        try
        {
            return ((ASN1Object)o).getEncoded();
        }
        catch (IOException e)
        {
            LOG.error("Failed to encode ASN.1 object", e);
            return new byte[0];
        }
    }

    private <T> List<T> getParsedValues(ASN1ObjectIdentifier attributeName, BiConsumer<Object, List<T>> parser)
    {
        var attr = attributeTable == null ? null : attributeTable.get(attributeName);
        if (attr == null)
        {
            return Collections.emptyList();
        }
        List<T> result = new ArrayList<>();
        for (Enumeration<?> e = attr.getAttrValues().getObjects(); e.hasMoreElements(); )
        {
            parser.accept(e.nextElement(), result);
        }
        return result;
    }

}
