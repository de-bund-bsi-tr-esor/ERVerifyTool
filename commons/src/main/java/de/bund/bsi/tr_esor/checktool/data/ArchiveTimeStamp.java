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
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Parsed ArchiveTimeStamp (partial hash tree + TSP).
 *
 * @author TT
 */
public class ArchiveTimeStamp implements ASN1Encodable
{

    private static final int TAGNO_DIGESTALGO = 0;

    private static final int TAGNO_ATTRIBUTES = 1;

    private static final int TAGNO_REDUCEDHASHTREE = 2;

    private static final Logger LOG = LoggerFactory.getLogger(ArchiveTimeStamp.class);

    /** Algorithm ID of hash algorithm. */
    private AlgorithmIdentifier digestAlgo = null;

    /** Attributes of the object. */
    private Attributes attributes = null;

    private List<PartialHashtree> reducedHashtree = null;

    private TimeStampToken timeStampToken;

    /**
     * Initializes the ArchiveTimeStamp by the given ASN1Encodable.
     *
     * @param obj ASN.1 object
     * @throws IOException
     */
    public ArchiveTimeStamp(ASN1Encodable obj) throws IOException
    {

        var indexOfLastElementInDef = -1; // number of element in definition, some may be skipped
        for (var element : Checked.cast(obj).to(ASN1Sequence.class))
        {
            if (element instanceof DERTaggedObject)
            {
                var tagged = (DERTaggedObject)element;
                switch (tagged.getTagNo())
                {
                    case TAGNO_DIGESTALGO:
                        indexOfLastElementInDef = checkSequence(indexOfLastElementInDef, 1);
                        digestAlgo = ASN1Utils.parseAlgorithmIdentifier(tagged.getObject());
                        break;
                    case TAGNO_ATTRIBUTES:
                        indexOfLastElementInDef = checkSequence(indexOfLastElementInDef, 2);
                        parseAttributes(tagged);
                        break;
                    case TAGNO_REDUCEDHASHTREE:
                        final var defPosRHT = 3;
                        indexOfLastElementInDef = checkSequence(indexOfLastElementInDef, defPosRHT);
                        parseReducedHashtree(tagged);
                        break;
                    default:
                        throw new IOException("unexpected tag number in ATS: " + tagged.getTagNo());
                }
            }
            else
            {
                final var defPosTsp = 4;
                indexOfLastElementInDef = checkSequence(indexOfLastElementInDef, defPosTsp);
                timeStampToken = parseTimeStampToken((ASN1Sequence)element);
            }
        }
    }

    private int checkSequence(int lastIndex, int thisIndex) throws IOException
    {
        if (lastIndex < thisIndex)
        {
            return thisIndex;
        }
        throw new IOException("unexpected element in ASN1Sequence for ATS");
    }

    private TimeStampToken parseTimeStampToken(ASN1Sequence e) throws IOException
    {
        Objects.requireNonNull(e, "ASN.1 encoded time stamp token");
        try
        {
            var encodedBytes = e.toASN1Primitive().getEncoded(ASN1Encoding.DER);
            Objects.requireNonNull(e, "encoded bytes");
            return new TimeStampToken(new CMSSignedData(encodedBytes));
        }
        catch (TSPException | CMSException ex)
        {
            throw new IOException("not valid (ATS-3)", ex);
        }
    }

    private void parseReducedHashtree(ASN1TaggedObject t) throws IOException
    {
        reducedHashtree = new ArrayList<>();
        var stt = ASN1Sequence.getInstance(t, false);
        for (var et : stt)
        {
            reducedHashtree.add(new PartialHashtree((ASN1Object)et));
        }
    }

    private void parseAttributes(ASN1TaggedObject t) throws IOException
    {
        // This tag is implicit, if only one attribute is present, the data is recognized as ASN1Sequence
        // (outer element of an attribute).
        if (t.getObject() instanceof ASN1Sequence)
        {
            attributes = Attributes.getInstance(new DLSet(t.getObject()));
        }
        else if (t.getObject() instanceof ASN1Set)
        {
            attributes = Attributes.getInstance(t.getObject());
        }
        else
        {
            throw new IOException("Attributes element in ATS is not of type SET");
        }
    }

    /**
     * Gets ID of hash algorithm.
     *
     * @return algorithm ID
     */
    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgo;
    }

    /**
     * Gets the date of TimeStamp.
     */
    public Date getSignDateFromTimeStamp()
    {
        if (timeStampToken == null)
        {
            return null;
        }

        return timeStampToken.getTimeStampInfo().getGenTime();
    }

    /**
     * Gets the OID from the TimeStampToken.
     */
    public String getOidFromTimeStamp()
    {
        if (timeStampToken == null)
        {
            return null;
        }
        return timeStampToken.getTimeStampInfo().getMessageImprintAlgOID().getId();
    }

    /**
     * Gets the partial hashtree with given index. By logic, returns the hash list of the idx-th node in the reduced hash tree counted from
     * documents on.
     *
     * @param idx index of partial hashtree
     * @return partial hashtree
     */
    public PartialHashtree getPartialHashtree(int idx)
    {
        if (reducedHashtree == null || reducedHashtree.size() <= idx)
        {
            return null;
        }
        return reducedHashtree.get(idx);
    }

    /**
     * Returns the number of partial hashtrees in list.
     */
    public int numberOfPartialHashtrees()
    {
        if (reducedHashtree == null)
        {
            return 0;
        }
        return reducedHashtree.size();
    }

    /**
     * Gets the ContentInfo with TimeStampToken as content correctly DER encoded for comparison in ER. This is NOT the encoded
     * ArchiveTimeStamp (reduced hash tree, ...)!
     *
     * @return the DER encoded ContentInfo with TimeStampToken as content
     * @throws IOException
     */
    public byte[] getContentOfTimeStampField() throws IOException
    {
        try (var ais = new ASN1InputStream(timeStampToken.getEncoded()))
        {
            var info = ContentInfo.getInstance(ais.readObject());
            return info.getEncoded(ASN1Encoding.DER);
        }
    }

    /**
     * Returns the (bouncycastle) TimeStampToken object.
     */
    public TimeStampToken getTimeStampToken()
    {
        return timeStampToken;
    }

    /**
     * Gets the attributes of the ArchiveTimeStamp.
     */
    public Attributes getAttributes()
    {
        return attributes;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        var ats = new ASN1EncodableVector();
        if (digestAlgo != null)
        {
            var t = new DERTaggedObject(false, TAGNO_DIGESTALGO, digestAlgo);
            ats.add(t);
        }
        if (attributes != null)
        {
            var t = new DERTaggedObject(false, TAGNO_ATTRIBUTES, attributes);
            ats.add(t);
        }
        if (reducedHashtree != null)
        {
            var va = new ASN1EncodableVector();
            for (var i = 0; i < reducedHashtree.size(); i++)
            {
                va.add(reducedHashtree.get(i).toASN1Primitive());
            }
            var t = new DERTaggedObject(false, TAGNO_REDUCEDHASHTREE, new DERSequence(va));
            ats.add(t);
        }

        try (var ais = new ASN1InputStream(timeStampToken.getEncoded()))
        {
            var info = ContentInfo.getInstance(ais.readObject());
            ats.add(info);
            return new DERSequence(ats);
        }
        catch (IOException e)
        {
            LOG.error("Invalid input data in TimeStampToken", e);
            return null;
        }
    }
}
