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
import java.util.Optional;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.util.encoders.Hex;


/**
 * Helper methods for ASN1 handling.
 *
 * @author HMA, TT
 */
public final class ASN1Utils
{

    private ASN1Utils()
    {
        // no instances
    }

    /**
     * Returns an algorithm identifier which is represented by a sequence containing the AOID and parameters. However, because implicit DER
     * encoding is allowed, be aware that the sequence tag(s) may be missing.
     *
     * @param data
     * @throws IOException
     */
    public static AlgorithmIdentifier parseAlgorithmIdentifier(ASN1Encodable data) throws IOException
    {
        return data instanceof ASN1ObjectIdentifier
            ? new AlgorithmIdentifier((ASN1ObjectIdentifier)data)
            : AlgorithmIdentifier.getInstance(Checked.cast(data).to(ASN1Sequence.class));
    }

    /**
     * Returns a human-readable string representing a signer ID.
     *
     * @param sid
     */
    public static String sidToString(SignerId sid)
    {
        return Optional.ofNullable(sid.getIssuer())
            .map(i -> i + "#" + sid.getSerialNumber())
            .orElse(Optional.ofNullable(sid.getSubjectKeyIdentifier()).map(Hex::toHexString).orElse(sid.toString()));
    }
}
