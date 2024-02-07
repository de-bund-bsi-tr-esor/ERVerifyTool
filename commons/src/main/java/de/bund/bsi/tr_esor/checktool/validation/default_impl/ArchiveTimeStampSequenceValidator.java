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

import java.util.Date;

import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampSequence;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.report.ATSChainReport;
import de.bund.bsi.tr_esor.checktool.validation.report.ATSSequenceReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Validator for ArchiveTimeStampSequence objects.
 *
 * @author TT, MO
 */
public class ArchiveTimeStampSequenceValidator extends BaseValidator<ArchiveTimeStampSequence, ErValidationContext, ATSSequenceReport>
{

    @Override
    protected ATSSequenceReport validateInternal(Reference ref, ArchiveTimeStampSequence toCheck)
    {
        var report = new ATSSequenceReport(ref);
        if (toCheck.isEmpty())
        {
            return report;
        }
        setupSecuredTimes(toCheck);
        for (var i = 0; i < toCheck.size(); i++)
        {
            var chain = toCheck.get(i);
            var chainRef = ref.newChild(Integer.toString(i));
            var ph = computeHashOfSequenceSoFar(toCheck, i, chainRef, report);

            report.addChild(callValidator(chain,
                chainRef,
                val -> ((ArchiveTimeStampChainValidator)val).setPrevChainHash(ph),
                ATSChainReport.class));
        }
        return report;
    }

    /**
     * For each ATS in the sequence, write into the context the time at which that ATS surely existed (because there is another time stamp
     * proving that).
     *
     * @param toCheck
     */
    private void setupSecuredTimes(ArchiveTimeStampSequence toCheck)
    {
        ArchiveTimeStamp lastAts = null;
        for (var chain : toCheck)
        {
            for (var ats : chain)
            {
                var secure = ats.getSignDateFromTimeStamp();
                if (lastAts != null)
                {
                    ctx.setSecureData(lastAts, secure);
                }
                lastAts = ats;
            }
        }
        ctx.setSecureData(lastAts, new Date());
    }

    /**
     * Returns the hash value of the ATS sequence up the before current position (null if there is none) using digest algorithm of current
     * ATS.
     *
     * @param toCheck
     * @param pos
     * @param ref for addressing a possible the problem in the report
     * @param report to write error message to
     */
    private byte[] computeHashOfSequenceSoFar(ArchiveTimeStampSequence toCheck, int pos, Reference ref, ATSSequenceReport report)
    {
        if (pos == 0)
        {
            return null;
        }
        var hashOID = toCheck.get(pos).get(0).getOidFromTimeStamp();
        var seq = new ArchiveTimeStampSequence();
        for (var i = 0; i < pos; i++)
        {
            seq.add(toCheck.get(i));
        }
        return computeHash(seq::getEncoded, hashOID, ref, report);
    }

    @Override
    protected Class<ErValidationContext> getRequiredContextClass()
    {
        return ErValidationContext.class;
    }

}
