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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampChain;
import de.bund.bsi.tr_esor.checktool.data.DataGroup;
import de.bund.bsi.tr_esor.checktool.data.DigestsToCover;
import de.bund.bsi.tr_esor.checktool.hash.Concatenation;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.ATSChainReport;
import de.bund.bsi.tr_esor.checktool.validation.report.ArchiveTimeStampReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;


/**
 * Validator for ArchiveTimeStampChain objects.
 *
 * @author TT, MO
 */
public class ArchiveTimeStampChainValidator extends BaseValidator<ArchiveTimeStampChain, ErValidationContext, ATSChainReport>
{

    private static final Logger LOG = LoggerFactory.getLogger(ArchiveTimeStampChainValidator.class);

    private ATSChainReport report;

    private byte[] prevChainHash;


    @Override
    protected ATSChainReport validateInternal(Reference ref, ArchiveTimeStampChain toCheck)
    {
        report = new ATSChainReport(ref);
        if (toCheck.isEmpty())
        {
            return report;
        }
        DigestsToCover digestsToCover;
        var digestOid = toCheck.get(0).getOidFromTimeStamp();

        try
        {
            if (prevChainHash == null)
            {
                digestsToCover = new DigestsToCover(ctx.getRequiredDigests(digestOid), ctx.isCheckForAdditionalHashes());
            }
            else
            {
                digestsToCover = getHashedConcatenation(ref, digestOid, ctx.getProfileName());
            }
            if (digestsToCover.isEmpty())
            {
                report.updateCodes(ValidationResultMajor.INDETERMINED,
                    "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError",
                    MinorPriority.MOST_IMPORTANT,
                    "no protected data to check",
                    ref);
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            LOG.debug("unsupported algorithm", e);
            report.updateCodes(ValidationResultMajor.INDETERMINED,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError",
                MinorPriority.MOST_IMPORTANT,
                "unsupported digest oid: " + digestOid,
                ref);
            return report;
        }

        for (var i = 0; i < toCheck.size(); i++)
        {
            var ats = toCheck.get(i);
            var atsRef = ref.newChild(Integer.toString(i));
            var isFirstChain = prevChainHash == null;
            var isFirstInChain = i == 0;
            var lastTimestampsContent = i == 0 ? null : timestampsContent(toCheck.get(i - 1));
            // Check for additional hashes only for the first ArchiveTimeStamp in each chain.
            var digestsToCoverThisRound = digestsToCover;

            // CHECKSTYLE:OFF
            report.addChild(callValidator(ats, atsRef, validator -> {
                ArchiveTimeStampValidator v = (ArchiveTimeStampValidator)validator;
                v.setDigestsToCover(digestsToCoverThisRound, digestOid);
                v.setPositionInChains(isFirstChain, isFirstInChain);
                v.setLastTimestampsContent(lastTimestampsContent);
                v.setArchiveTimestampSequenceHashSoFar(prevChainHash);
            }, ArchiveTimeStampReport.class));
            // CHECKSTYLE:ON

            // For the next timestamps in a chain, only the hash of the previous timestamp is expected
            // Other hashes are arbitrary and should not be checked
            var prevTspHash = new HashMap<Reference, byte[]>();
            prevTspHash.put(new Reference("prev TSP of chain"), computeHash(ats::getContentOfTimeStampField, digestOid, atsRef, report));
            digestsToCover = new DigestsToCover(prevTspHash, false);
        }
        return report;
    }

    private byte[] timestampsContent(ArchiveTimeStamp ats)
    {
        try
        {
            return ats.getContentOfTimeStampField();
        }
        catch (IOException e)
        {
            return null;
        }
    }

    private DigestsToCover getHashedConcatenation(Reference id, String digestOid, String profileName) throws NoSuchAlgorithmException
    {
        Map<Reference, byte[]> unsortedDigestsMap = new HashMap<>();
        Map<Reference, byte[]> sortedDigestsMap = new HashMap<>();
        for (var digestEntry : ctx.getRequiredDigests(digestOid).entrySet())
        {
            // alternative sorted variant equivalent to other hash concatenations
            List<byte[]> hashes = new ArrayList<>(2);
            hashes.add(digestEntry.getValue());
            hashes.add(prevChainHash);
            var dg = new DataGroup(hashes, digestOid);
            sortedDigestsMap.put(digestEntry.getKey(), dg.getDoubleHash());

            // unsorted variant as specified in RFC
            var concatHash = Concatenation.concat(digestEntry.getValue(), prevChainHash);
            unsortedDigestsMap.put(digestEntry.getKey(), computeHash(() -> concatHash, digestOid, id, report));
        }

        var expectSortedHashes = Configurator.getInstance().hashSortingMode(profileName);
        return new DigestsToCover(sortedDigestsMap, unsortedDigestsMap, ctx.isCheckForAdditionalHashes(), expectSortedHashes);
    }

    /**
     * Sets the hash of previous ATS chains, if existing.
     *
     * @param prevChainHash
     */
    void setPrevChainHash(byte[] prevChainHash)
    {
        this.prevChainHash = prevChainHash;
    }

    @Override
    protected Class<ErValidationContext> getRequiredContextClass()
    {
        return ErValidationContext.class;
    }
}
