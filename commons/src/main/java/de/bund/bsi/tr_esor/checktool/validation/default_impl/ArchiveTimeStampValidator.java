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
package de.bund.bsi.tr_esor.checktool.validation.default_impl;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.bouncycastle.util.encoders.Hex;

import de.bund.bsi.tr_esor.checktool.conf.HashSortingMode;
import de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.data.DataGroup;
import de.bund.bsi.tr_esor.checktool.data.DigestsToCover;
import de.bund.bsi.tr_esor.checktool.hash.Concatenation;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.AlgorithmValidityReport;
import de.bund.bsi.tr_esor.checktool.validation.report.ArchiveTimeStampReport;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;


/**
 * Validator for ArchiveTimeStamp objects. Throught the DigestsToCover-object, the validator can be parametrized to check for the occurrence
 * of additional hashes. If this is set to true, the validation will fail in case there are more hash values present in the ArchiveTimeStamp
 * than given through setDigestsToCover. If no digests are given, no check is done. If checkForAdditionalHashes is set to false, validation
 * will fail if one of the given digests to cover is not present, but additional hashes in the ArchiveTimeStamp will be accepted. This
 * functionality is required for the check of subsequent timestamps of an ArchiveTimeStampChain, as the subsequent timestamps will contain
 * the hashes of other timestamps in the first entry inside the partial hash tree.
 *
 * @author MO
 */
public class ArchiveTimeStampValidator extends BaseValidator<ArchiveTimeStamp, ErValidationContext, ArchiveTimeStampReport>
{

    private byte[] lastTimestampsContent;

    private byte[] archiveTimestampSequenceHashSoFar;

    private boolean isFirstChain;

    private boolean isFirstInChain;

    private ArchiveTimeStampReport atsReport;

    private FormatOkReport formatOk;

    private String hashOID;

    private DigestsToCover requiredCoveredDigestValues;

    private boolean usesDoubleHash;

    private String hashOIDInPrevATS;

    @Override
    protected ArchiveTimeStampReport validateInternal(Reference ref, ArchiveTimeStamp ats)
    {
        atsReport = new ArchiveTimeStampReport(ref);
        formatOk = new FormatOkReport(ref);
        var secureDate = ctx.getSecureDate(ats);

        checkAscendingSecureDate(ats.getSignDateFromTimeStamp(), secureDate, ref);
        atsReport.addChild(checkDigestAlgorithm(ats, ref, secureDate));
        fillInReducedHashTree(ats);
        checkHashTree(ats);
        checkTimeStampToken(ref, ats);
        atsReport.setFormatOk(formatOk);
        return atsReport;
    }

    /**
     * Digest algorithm must be checked individually for each ATS because same algorithm can be both suitable and unsuitable as secured data
     * changes.
     *
     * @param ats
     * @param secureDate
     */
    private AlgorithmValidityReport checkDigestAlgorithm(ArchiveTimeStamp ats, Reference ref, Date secureDate)
    {
        var oidFromTsp = ats.getOidFromTimeStamp();
        hashOID = oidFromTsp;
        ctx.setPossibleAlgorithmUsage(oidFromTsp, secureDate);
        Reference oidRef;

        if (ats.getDigestAlgorithm() == null)
        {
            oidRef = ref.newChild("tsp.messageImprintAlgOid");
        }
        else
        {
            var oidFromAtsAttribute = ats.getDigestAlgorithm().getAlgorithm().getId();
            oidRef = ref.newChild("attributeDigestAlgorithm");
            hashOID = oidFromAtsAttribute;
            if (!oidFromTsp.equals(oidFromAtsAttribute))
            {
                setInvalidFormat(formatOk, ref, "Algorithm attribute of ATS does not match the digest algorithm used in the TSP");
            }
        }

        if (!ctx.isAlgorithmDeclared(oidFromTsp))
        {
            setInvalidFormat(ctx.getFormatOk(), ref, "Digest algorithm not declared in evidence record/algorithms");
        }
        if (hashOIDInPrevATS != null && !hashOIDInPrevATS.equals(oidFromTsp))
        {
            setInvalidFormat(ctx.getFormatOk(), ref, "Digest algorithm does not match digest of previous ATs in same chain");
        }

        var usage = AlgorithmUsage.createHashed(hashOID, secureDate);
        return callValidator(usage, oidRef, null, () -> new AlgorithmValidityReport(oidRef, oidFromTsp), AlgorithmValidityReport.class);
    }

    /**
     * Check that the time stamp is older than it's secure date, this ensures that all time stamps are sorted in ascending order.
     *
     * @param signDateFromTimeStamp
     * @param secureDate
     */
    private void checkAscendingSecureDate(Date signDateFromTimeStamp, Date secureDate, Reference ref)
    {
        if (!signDateFromTimeStamp.before(secureDate))
        {
            ctx.getFormatOk().invalidate("The time of ArchiveTimeStamp is before the time of the previous ArchiveTimeStamp!", ref);
        }
    }

    private void setInvalidFormat(ReportPart target, Reference ref, String msg)
    {
        target.updateCodes(ValidationResultMajor.INVALID,
            ValidationResultMinor.INVALID_FORMAT.toString(),
            MinorPriority.IMPORTANT,
            msg,
            ref);
    }

    private void checkTimeStampToken(Reference atsID, ArchiveTimeStamp ats)
    {
        var tsp = atsID.newChild("tsp");
        // CHECKSTYLE:OFF
        atsReport.addChild(callValidator(ats.getTimeStampToken(), tsp, v -> {
            if (v instanceof BaseTimeStampValidator)
            {
                var validator = (BaseTimeStampValidator)v;
                validator.setSourceOfRootHash(sourceOfRootHash(ats, atsID));
            }
        }, TimeStampReport.class));
        // CHECKSTYLE:ON
    }

    /**
     * This determines the source value of the root hash. The source value is required for an eIDAS compliant timestamp validation.
     */
    private byte[] sourceOfRootHash(ArchiveTimeStamp ats, Reference atsID)
    {
        // if a previous hash tree level exists, that is the source of the root hash
        var dataGroup = rootDataGroupOfReducedHashTree(ats);
        if (dataGroup != null && (usesDoubleHash || !dataGroup.needsDataForCheck()))
        {
            return dataGroup.sortedAndConcatenatedHashes();
        }
        // if there is only a single leaf in the hash tree, the root's hash source depends on the single data
        else if (isFirstChain && isFirstInChain)
        {
            return ctx.singleProtectedData();
        }
        else if (ats.numberOfPartialHashtrees() == 1 && ats.getPartialHashtree(0).size() == 1)
        {
            if (!isFirstChain && isFirstInChain)
            {
                return Concatenation.concat(computeHash(() -> ctx.singleProtectedData(), ats.getOidFromTimeStamp(), atsID, atsReport),
                    archiveTimestampSequenceHashSoFar);
            }
            else
            {
                return lastTimestampsContent;
            }
        }
        else
        {
            return null;
        }
    }

    /**
     * Sets all digest values which must be covered by this ATS in order to make it valid. Validation will fail if all digest values are not
     * completely found in the first partial hash tree (group) or in the TSP itself.
     *
     * @param digests The digests for first ATS in chain, this contains the digest values of all protected elements and, if a previous
     *     chain exists, the digest of the ATS sequence up to the last chain. For subsequent ATS in a chain, this contains only the digest
     *     of the TSP of the previous ATS. Keys are free strings for debugging purposes only.
     * @param hashOIDInPreviousATS In case this ATS is not the first in chain, the algorithm specified here is used in the chain so far.
     *     Validation will fail if this ATS uses other digest algorithm in same chain.
     */
    void setDigestsToCover(DigestsToCover digests, String hashOIDInPreviousATS)
    {
        requiredCoveredDigestValues = digests;
        this.hashOIDInPrevATS = hashOIDInPreviousATS;
    }

    /**
     * Asserts that required document hash(es) are found in the partial hash tree or tsp and that the partial hash tree if exists is
     * consistent.
     *
     * @param ats
     */
    private void checkHashTree(ArchiveTimeStamp ats)
    {
        var actuallyCoveredDigests = ats.numberOfPartialHashtrees() == 0 ? Collections.singletonList(ats.getTimeStampToken()
            .getTimeStampInfo()
            .getMessageImprintDigest()) : ats.getPartialHashtree(0);

        checkProtectedElements(actuallyCoveredDigests);
        if (ats.numberOfPartialHashtrees() != 0)
        {
            checkHashes(ats);
        }
    }

    private void checkHashes(ArchiveTimeStamp ats)
    {
        if (rootDataGroupOfReducedHashTree(ats) == null)
        {
            formatOk.updateCodes(ValidationResultMajor.INVALID,
                ValidationResultMinor.HASH_VALUE_MISMATCH.toString(),
                MinorPriority.MOST_IMPORTANT,
                "hash tree root hash does not match timestamp",
                atsReport.getReference().newChild("hashTree"));
        }
    }

    /**
     * Returns the root data group of the reduced hash tree whose hash is ensured to match the actual timestamp message hash. Various
     * methods to compute the hash from a data groups are considered. Returns null otherwise.
     */
    private DataGroup rootDataGroupOfReducedHashTree(ArchiveTimeStamp ats)
    {
        var timeStampMessageHash = ats.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest();
        // find out which is the actual hash construction method for the root hash and return the last data group
        // if any
        for (var useDoubleHash : new boolean[]{true, false})
        {
            Function<DataGroup, byte[]> hashFunction = useDoubleHash ? DataGroup::getDoubleHash : DataGroup::getHash;
            for (var computeMissing : new boolean[]{true, false})
            {
                var lastGroup = rootDataGroup(ats, hashFunction, computeMissing);
                if (lastGroup != null)
                {
                    var lastGroupsHash = hashFunction.apply(lastGroup);

                    if (Arrays.equals(lastGroupsHash, timeStampMessageHash))
                    {
                        usesDoubleHash = useDoubleHash;
                        return lastGroup;
                    }
                }
            }
        }
        return null;
    }

    private void fillInReducedHashTree(ArchiveTimeStamp ats)
    {
        // Attributes left out deliberately, because official dss-x schema type vr:AttributeType is insufficient
        // to carry useful information, as no OID can be specified.
        var rht = XmlHelper.FACTORY_OASIS_VR.createArchiveTimeStampValidityTypeReducedHashTree();
        for (var i = 0; i < ats.numberOfPartialHashtrees(); i++)
        {
            var pht = XmlHelper.FACTORY_OASIS_VR.createArchiveTimeStampValidityTypeReducedHashTreePartialHashTree();
            for (var v : ats.getPartialHashtree(i))
            {
                var value = XmlHelper.FACTORY_OASIS_VR.createHashValueType();
                value.setHashValue(v);
                pht.getHashValue().add(value);
            }
            rht.getPartialHashTree().add(pht);
        }
        if (!rht.getPartialHashTree().isEmpty())
        {
            atsReport.getFormatted().setReducedHashTree(rht);
        }
    }

    private void checkProtectedElements(List<byte[]> atsHashes)
    {
        var hashSortingMode = requiredCoveredDigestValues.getHashSortingMode();
        if (!requiredCoveredDigestValues.isEmpty() && hashSortingMode == HashSortingMode.BOTH)
        {
            var missingDigestIds = missingDigestsForHashmodeBoth(atsHashes);
            if (!missingDigestIds.isEmpty())
            {
                handleMissingDigests(missingDigestIds);
            }
        }
        else if (!requiredCoveredDigestValues.isEmpty())
        {
            if (atsHashes.size() < requiredCoveredDigestValues.streamHashes().count())
            {
                formatOk.updateCodes(ValidationResultMajor.INVALID,
                    ValidationResultMinor.HASH_VALUE_MISMATCH.toString(),
                    MinorPriority.MOST_IMPORTANT,
                    "Too many protected elements",
                    atsReport.getReference().newChild("protectedElements"));
            }

            var missingDigestIds = missingDigestsForDefaultHashMode(atsHashes);
            if (!missingDigestIds.isEmpty())
            {
                missingDigestIds.forEach(atsReport::addIdOfMissingHash);
                if (wouldAlternativeHashModeBeCorrect(atsHashes, hashSortingMode))
                {
                    // do not check additional hashes if the mode was mistaken
                    return;
                }
                handleMissingDigests(missingDigestIds);
            }
        }

        if (requiredCoveredDigestValues.isCheckForAdditionalHashes())
        {
            checkForAdditionalHashes(atsHashes);
        }
    }

    private boolean wouldAlternativeHashModeBeCorrect(List<byte[]> atsHashes, HashSortingMode hashSortingMode)
    {
        if (requiredCoveredDigestValues.hasAlternativeHashes() && missingDigestsForAlternativeHashMode(atsHashes).isEmpty())
        {
            // Name of the detected mode is opposite of the configured mode
            var detectedHashMode = HashSortingMode.SORTED.equals(hashSortingMode) ? "unsorted (RFC 4998)" : "sorted";
            formatOk.updateCodes(ValidationResultMajor.INDETERMINED,
                ValidationResultMinor.HASH_VALUE_MISMATCH.toString(),
                MinorPriority.NORMAL,
                String.format(
                    "The hashes present in the evidence record do not match the mode (sorted/unsorted) given by the configuration. The hashes present seem to conform to the %s hash mode.",
                    detectedHashMode),
                atsReport.getReference().newChild("protectedElements"));
            return true;
        }
        return false;
    }

    private Set<Reference> missingDigestsForHashmodeBoth(List<byte[]> atsHashes)
    {
        var missingDigestIds = missingDigestsForDefaultHashMode(atsHashes);
        if (requiredCoveredDigestValues.hasAlternativeHashes())
        {
            var missingDigestIdsAlternativeSortMode = missingDigestsForAlternativeHashMode(atsHashes);
            // Only the intersection is not represented through any sorting mode
            missingDigestIds.retainAll(missingDigestIdsAlternativeSortMode);
        }
        return missingDigestIds;
    }

    private Set<Reference> missingDigestsForDefaultHashMode(List<byte[]> atsHashes)
    {
        return requiredCoveredDigestValues.streamEntries()
            .filter(entry -> atsHashes.stream().noneMatch(hash -> Arrays.equals(hash, entry.getValue())))
            .map(Entry::getKey)
            .collect(Collectors.toSet());
    }

    private Set<Reference> missingDigestsForAlternativeHashMode(List<byte[]> atsHashes)
    {
        return requiredCoveredDigestValues.streamAlternativeEntries()
            .filter(entry -> atsHashes.stream().noneMatch(hash -> Arrays.equals(hash, entry.getValue())))
            .map(Entry::getKey)
            .collect(Collectors.toSet());
    }

    private void checkForAdditionalHashes(List<byte[]> atsHashes)
    {
        var additionalHashes = getAdditionalHashes(atsHashes);
        if (!additionalHashes.isEmpty())
        {
            handleAdditionalHashes(additionalHashes);
        }
    }

    private List<byte[]> getAdditionalHashes(List<byte[]> atsHashes)
    {
        return atsHashes.stream()
            .filter(existent -> requiredCoveredDigestValues.streamAllHashes().noneMatch(required -> Arrays.equals(existent, required)))
            .collect(Collectors.toList());
    }

    private void handleAdditionalHashes(List<byte[]> additionalHashes)
    {
        var hexHashes = additionalHashes.stream().map(Hex::encode).map(String::new).collect(Collectors.toList());
        var expectedReferences = requiredCoveredDigestValues.streamReferences().map(Reference::toString).collect(Collectors.toList());
        formatOk.updateCodes(ValidationResultMajor.INVALID,
            ValidationResultMinor.HASH_VALUE_MISMATCH.toString(),
            MinorPriority.IMPORTANT,
            "The evidence record contains additional protected hash values. Expected hashes for: "
                + expectedReferences
                + ". Additional hashes:"
                + hexHashes,
            atsReport.getReference().newChild("protectedElements"));
    }

    private void handleMissingDigests(Set<Reference> missingDigestIds)
    {
        missingDigestIds.forEach(atsReport::addIdOfMissingHash);
        formatOk.updateCodes(ValidationResultMajor.INVALID,
            ValidationResultMinor.HASH_VALUE_MISMATCH.toString(),
            MinorPriority.MOST_IMPORTANT,
            "Missing digest(s) for: " + missingDigestIds,
            atsReport.getReference().newChild("protectedElements"));
    }

    /**
     * Returns the root data group of a reduced hash tree. This method works both in the case that the computed hash of one group must be
     * added to the next group and in the case that it is already present in that group.
     *
     * @param hashFunction Defines how to compute a hash value of a data group. This method can handle different cases of handling data
     *     groups with exactly one contained hash value.
     * @param handleHashesAsSet handles hashes in data groups as set (thus only considering one hash of multiple equal hashes for the
     *     group hash)
     */
    private DataGroup rootDataGroup(ArchiveTimeStamp ats, Function<DataGroup, byte[]> hashFunction, boolean handleHashesAsSet)
    {
        DataGroup lastGroup = null;
        for (var i = 0; i < ats.numberOfPartialHashtrees(); i++)
        {
            var group = new DataGroup(ats.getPartialHashtree(i), hashOID);
            group.setHandleHashesAsSet(handleHashesAsSet);
            if (lastGroup != null)
            {
                group.addHash(hashFunction.apply(lastGroup));
            }
            lastGroup = group;
        }
        return lastGroup;
    }

    void setLastTimestampsContent(byte[] lastTimestampsContent)
    {
        this.lastTimestampsContent = lastTimestampsContent;
    }

    void setArchiveTimestampSequenceHashSoFar(byte[] archiveTimestampSequenceHashSoFar)
    {
        this.archiveTimestampSequenceHashSoFar = archiveTimestampSequenceHashSoFar;
    }

    void setPositionInChains(boolean isFirstChain, boolean isFirstInChain)
    {
        this.isFirstChain = isFirstChain;
        this.isFirstInChain = isFirstInChain;
    }

    @Override
    protected Class<ErValidationContext> getRequiredContextClass()
    {
        return ErValidationContext.class;
    }

    /**
     * Taken from BSI TR-ESOR-VR V 1.3 p.12 + "Algo Mismatch" because no defined Minor covers that case.
     */
    private enum ValidationResultMinor
    {

        INVALID_FORMAT("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/invalidFormat"),
        HASH_VALUE_MISMATCH("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/hashValueMismatch"),
        SIGNATURE_FORMAT_NOT_SUITABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor//il/algorithm#signatureAlgorithmNotSuitable"),
        PARAMETER_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError"),
        SIGNATURE_FORMAT_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureFormatNotSupported"),
        SIGNATURE_ALGORITHM_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor//il/algorithm#signatureAlgorithmNotSupported"),
        UNKNOWN_ATTRIBUTE("http://www.bsi.bund.de/tr-esor/api/1.1/resultminor/unknownAttribute"),
        NOT_SUPPORTED("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/arl/notSupported");

        private final String value;

        ValidationResultMinor(String uri)
        {
            this.value = uri;
        }

        @Override
        public String toString()
        {
            return value;
        }

    }
}
