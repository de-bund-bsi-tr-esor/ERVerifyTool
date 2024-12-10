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

import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;


/**
 * Parsed evidence record with format neutral getters for the elements.
 *
 * @author JKO, KK, TOC, TT
 */
public class EvidenceRecord
{

    private final int version;

    /** List of all used hash algorithms. */
    private final List<AlgorithmIdentifier> digestAlgos;

    /** Archive timestamp sequence. */
    private final ArchiveTimeStampSequence atss;

    /** Crypto info. */
    private CryptoInfo cryptoInfo = null;

    /** Encryption info. */
    private EncryptionInfo encryptInfo = null;


    /**
     * Creates a new EvidenceRecord object based on the given data.
     *
     * @param version version number of ER
     * @param digestAlgos list of hash algorithms
     * @param atss the used archive timestamp sequence
     * @param cryptoInfo info about crypto
     * @param encryptInfo info about encryption
     */
    public EvidenceRecord(int version, List<AlgorithmIdentifier> digestAlgos, ArchiveTimeStampSequence atss, CryptoInfo cryptoInfo,
        EncryptionInfo encryptInfo)
    {
        this.version = version;
        this.digestAlgos = digestAlgos;
        this.atss = atss;
        this.cryptoInfo = cryptoInfo;
        this.encryptInfo = encryptInfo;
    }

    /**
     * Gets version number.
     *
     * @return version number
     */
    public int getVersion()
    {
        return version;
    }

    /**
     * Gets list of hash algorithms.
     *
     * @return list of hash algorithms
     */
    public List<String> getDigestAlgorithms()
    {
        return digestAlgos.stream().map(a -> a.getAlgorithm().getId()).collect(Collectors.toList());
    }

    /**
     * Gets crypto info.
     *
     * @return crypto info
     */
    public CryptoInfo getCryptoInfo()
    {
        return cryptoInfo;
    }

    /**
     * Gets encryption info.
     *
     * @return encryption info
     */
    public EncryptionInfo getEncryptionInfo()
    {
        return encryptInfo;
    }

    /**
     * Returns the archive time stamp sequence.
     */
    public ArchiveTimeStampSequence getAtss()
    {
        return atss;
    }
}
