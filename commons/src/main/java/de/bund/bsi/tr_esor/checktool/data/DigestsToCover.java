package de.bund.bsi.tr_esor.checktool.data;

import java.util.Map;
import java.util.stream.Stream;

import de.bund.bsi.tr_esor.checktool.conf.HashSortingMode;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Class for storing lists of digests that should be covered by a specific timestamp and appropriate configuration. Supports that a
 * different hash mode (sorted/unsorted) can be inserted to check.
 */
public class DigestsToCover
{

    private final Map<Reference, byte[]> hashes;

    private final Map<Reference, byte[]> alternativeHashes;

    private final HashSortingMode hashSortingMode;

    private boolean checkForAdditionalHashes;

    /**
     * Constructor for use cases where there is no alternative of sorted and unsorted hashes, i.e. all cases except for the first timestamp
     * of an ArchiveTimestampChain produced by a rehash.
     *
     * @param hashes Map of the references and the hashes generated for them
     * @param checkForAdditionalHashes set to true to expect that no additional hashes not given by hashes are covered by the evidence
     *     record.
     */
    public DigestsToCover(Map<Reference, byte[]> hashes, boolean checkForAdditionalHashes)
    {
        this.hashes = hashes;
        this.checkForAdditionalHashes = checkForAdditionalHashes;
        this.alternativeHashes = null; // NOPMD No alternatives given
        this.hashSortingMode = null; // NOPMD not needed in this case
    }

    /**
     * Constructor for use cases where there is an alternative of sorted and unsorted hashes, i.e. only where the first timestamp of an
     * ArchiveTimestampChain produced by a rehash.
     *
     * @param sortedHashes Map of the references and the hashes generated for them if hashes are ordered before generating the root
     *     hash
     * @param unsortedHashes Map of the references and the hashes generated for them if hashes are generated according to the RFC
     * @param checkForAdditionalHashes set to true to expect that no additional hashes not given by hashes are covered by the evidence
     *     record.
     * @param expectSortedHashes set to true to expect the sorted hashes to be contained in the ER
     */
    public DigestsToCover(Map<Reference, byte[]> sortedHashes, Map<Reference, byte[]> unsortedHashes, boolean checkForAdditionalHashes,
        HashSortingMode expectSortedHashes)
    {
        this.checkForAdditionalHashes = checkForAdditionalHashes;
        this.hashSortingMode = expectSortedHashes;
        if (HashSortingMode.SORTED == hashSortingMode)
        {
            this.hashes = sortedHashes;
            this.alternativeHashes = unsortedHashes;
        }
        else
        {
            this.hashes = unsortedHashes;
            this.alternativeHashes = sortedHashes;
        }
    }

    /**
     * Returns true, if the validator should check for additional hashes beeing present in the evidence record
     */
    public boolean isCheckForAdditionalHashes()
    {
        return checkForAdditionalHashes;
    }

    /**
     * Get the hash sorting mode expected for this DigestsToCover. Might be null if no alternative hashes are present or any of the
     * HashSortingMode enum values.
     */
    public HashSortingMode getHashSortingMode()
    {
        return hashSortingMode;
    }

    /**
     * returns true if no hashes are contained
     */
    public boolean isEmpty()
    {
        return hashes.isEmpty();
    }

    /**
     * Stream the references that are covered by this DigestsToCover
     */
    public Stream<Reference> streamReferences()
    {
        return hashes.keySet().stream();
    }

    /**
     * Stream the hashes expected by this DigestsToCover
     */
    public Stream<byte[]> streamHashes()
    {
        return hashes.values().stream();
    }

    /**
     * Stream all (sorted and unsorted) hashes expected by this DigestsToCover
     */
    public Stream<byte[]> streamAllHashes()
    {
        if (alternativeHashes == null || alternativeHashes.isEmpty())
        {
            return hashes.values().stream();
        }
        else
        {
            return Stream.concat(hashes.values().stream(), alternativeHashes.values().stream());
        }
    }

    /**
     * Check if this DigestsToCover contains alternative hashes
     */
    public boolean hasAlternativeHashes()
    {
        return alternativeHashes != null && !alternativeHashes.isEmpty();
    }


    /**
     * Stream entries consisting of References and the hash values
     */
    public Stream<Map.Entry<Reference, byte[]>> streamEntries()
    {
        return hashes.entrySet().stream();
    }

    /**
     * Stream entries consisting of References and the hash values for the alternative hash mode. This will only work if alternative hashes
     * are present.
     */
    public Stream<Map.Entry<Reference, byte[]>> streamAlternativeEntries()
    {
        return alternativeHashes.entrySet().stream();
    }

    /**
     * Disable check for additional hashes
     */
    public void disableCheckForAdditionalHashes()
    {
        checkForAdditionalHashes = false;
    }

}
