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
package de.bund.bsi.tr_esor.checktool.entry;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;

import de.bund.bsi.tr_esor.checktool.data.ASN1Utils;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Helper class for finding embedded evidence record in a CAdES-E-ERS structure and for providing
 *
 * @author HMA, TT
 */
public class CmsSignedDataReader
{

    /** for detached */
    public static final ASN1ObjectIdentifier OID_EXTERNAL = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.50");

    /** for encapsulated */
    private static final ASN1ObjectIdentifier OID_INTERNAL = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.2.49");

    private final CMSSignedData cms;

    private final Reference ref;

    private final ASN1ObjectIdentifier oid;

    private final Map<Reference, SignerId> signerIdByReference = new HashMap<>();

    private final Map<Reference, Integer> posByReference = new HashMap<>();

    /**
     * Creates a new instance.
     *
     * @param data
     * @param ref
     */
    public CmsSignedDataReader(CMSSignedData data, Reference ref)
    {
        this.cms = data;
        this.ref = ref;
        oid = isDetached() ? OID_EXTERNAL : OID_INTERNAL;
    }

    /**
     * Returns all embedded evidence records.
     *
     * @throws IOException
     */
    public Map<Reference, EvidenceRecord> getEmbeddedErs() throws IOException
    {
        Map<Reference, EvidenceRecord> result = new HashMap<>();

        for (var signerInformation : cms.getSignerInfos())
        {
            var unsignedAttributes = signerInformation.getUnsignedAttributes();
            if (unsignedAttributes == null)
            {
                continue;
            }
            var all = unsignedAttributes.getAll(oid);
            for (var i = 0; i < all.size(); i++)
            {
                var attribute = (Attribute)all.get(i);
                var encodables = attribute.getAttributeValues();
                var asn1Encodable = encodables[0];
                var encodedER = asn1Encodable.toASN1Primitive().getEncoded();
                var erRef = ref.newChild(ASN1Utils.sidToString(signerInformation.getSID())).newChild(Integer.toString(i));

                result.put(erRef, new ASN1EvidenceRecordParser().parse(encodedER));
                signerIdByReference.put(erRef, signerInformation.getSID());
                posByReference.put(erRef, Integer.valueOf(i));
            }
        }
        return result;
    }

    /**
     * Returns the content info minus the referenced evidence records and all subsequence evidence records for the same signer.
     *
     * @param erRef
     * @throws IOException
     */
    public byte[] getContentInfoProtectedByEr(Reference erRef) throws IOException
    {
        var sid = signerIdByReference.get(erRef);
        if (sid == null)
        {
            return cms.getEncoded();
        }
        return cmsWithout(cms, sid, oid, posByReference.get(erRef).intValue());
    }

    /**
     * Returns <code>true</code> if signature is detached.
     */
    public final boolean isDetached()
    {
        return cms.isDetachedSignature();
    }

    /**
     * Returns a CMS signed data which is equal to the given one except that the i-th and all further values of the specified unsigned
     * attribute in the specified signer are removed.
     *
     * @param cms
     * @param sid
     * @param oid
     * @param i
     * @throws IOException
     */
    @SuppressWarnings("PMD.NullAssignment")
    private static byte[] cmsWithout(CMSSignedData cms, SignerId sid, ASN1ObjectIdentifier oid, int i) throws IOException
    {
        List<SignerInformation> si = new ArrayList<>();
        for (var signerInformation : cms.getSignerInfos())
        {
            if (signerInformation.getSID().equals(sid))
            {
                var at = signerInformation.getUnsignedAttributes();
                var all = at.getAll(oid);
                at = at.remove(oid);
                for (var k = 0; k < i; k++)
                {
                    at = at.add(oid, all.get(k));
                }
                if (at.size() == 0) // cannot happen in a correct CAdES-E-ERS structure
                {
                    at = null;
                }
                si.add(SignerInformation.replaceUnsignedAttributes(signerInformation, at));
            }
            else
            {
                si.add(signerInformation);
            }
        }
        return CMSSignedData.replaceSigners(cms, new SignerInformationStore(si)).getEncoded();
    }
}
