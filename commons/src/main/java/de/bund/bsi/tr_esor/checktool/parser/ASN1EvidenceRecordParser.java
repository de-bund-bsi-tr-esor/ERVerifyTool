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
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import de.bund.bsi.tr_esor.checktool.data.ASN1Utils;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampSequence;
import de.bund.bsi.tr_esor.checktool.data.Checked;
import de.bund.bsi.tr_esor.checktool.data.CryptoInfo;
import de.bund.bsi.tr_esor.checktool.data.EncryptionInfo;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;


/**
 * Parses a DER encoded EvidenceRecord to an EvidenceRecord object.
 *
 * @author JKO, TOC
 */
public class ASN1EvidenceRecordParser implements Parser<EvidenceRecord>
{

    private static final int BUF_SIZE = 133;

    private static final int TAGNO_CRYPTO_INFOS = 0;

    private static final int TAGNO_ENCRYPTION_INFO = 1;

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
        var buf = new byte[BUF_SIZE];
        var length = input.read(buf, 0, BUF_SIZE);
        input.reset();

        final var sequenceTag = 0x30;
        if (length < BUF_SIZE || buf[0] != sequenceTag)
        {
            return false;
        }

        var versionOffset = 1 + getNumberLengthOctets(buf, 1);
        final var integerTag = 0x02;
        return buf[versionOffset] == integerTag && buf[versionOffset + 3] == sequenceTag;
    }

    private int getNumberLengthOctets(byte[] buffer, int offset)
    {
        final var indefiniteLength = (byte)0x80;
        if (buffer[offset] == indefiniteLength)
        {
            return 1;
        }
        if ((buffer[offset] & indefiniteLength) == 0)
        {
            return 1;
        }
        return 1 + (0x7f & buffer[offset]);
    }

    @Override
    public EvidenceRecord parse() throws IOException
    {
        return parse(input.readAllBytes());
    }

    /**
     * Parses the given DER encoded EvidenceRecord.
     *
     * @param derEncodedER
     * @return EvidenceRecord
     * @throws IOException
     */
    public EvidenceRecord parse(byte[] derEncodedER) throws IOException
    {

        return parse(ASN1Primitive.fromByteArray(derEncodedER));
    }

    private EvidenceRecord parse(ASN1Object asn1Object) throws IOException
    {

        var rootSequence = Checked.cast(asn1Object).to(ASN1Sequence.class);
        var iter = rootSequence.iterator();
        // position 0 - version
        var asn1Version = Checked.cast(iter.next()).to(ASN1Integer.class);
        var version = asn1Version.getValue().intValue();
        // position 1
        // get all digest algorithms from digestAlgorithm sequence in the asn.1 this data is stored in
        // sequence[AlgoIdentifier], AlgoIdentifier is a sequence[digestAlgo, parameter]
        List<AlgorithmIdentifier> digestAlgos = new ArrayList<>();
        var algoList = Checked.cast(iter.next()).to(ASN1Sequence.class);
        for (var algo : algoList)
        {
            digestAlgos.add(ASN1Utils.parseAlgorithmIdentifier(algo));
        }

        // check crypto info (optional tagged object)
        var element = iter.next();
        CryptoInfo cryptoInfo = null;
        if (element instanceof ASN1TaggedObject && ((ASN1TaggedObject)element).getTagNo() == TAGNO_CRYPTO_INFOS)
        {
            cryptoInfo = new CryptoInfo(ASN1Sequence.getInstance((ASN1TaggedObject)element, false));
            element = iter.next();
        }

        // check encryption info (optional tagged object)
        EncryptionInfo encryptInfo = null;
        if (element instanceof ASN1TaggedObject && ((ASN1TaggedObject)element).getTagNo() == TAGNO_ENCRYPTION_INFO)
        {
            encryptInfo = new EncryptionInfo(ASN1Sequence.getInstance((ASN1TaggedObject)element, false));
            element = iter.next();
        }

        // ArchiveTimestampSequence
        var atss = new ArchiveTimeStampSequence(element);
        return new EvidenceRecord(version, digestAlgos, atss, cryptoInfo, encryptInfo);
    }
}
