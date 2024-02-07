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
package de.bund.bsi.tr_esor.checktool.validation.report;

import de.bund.bsi.tr_esor.checktool.xml.VRCreator;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import de.bund.bsi.tr_esor.vr.EvidenceRecordValidityType.ArchiveTimeStampSequence;
import de.bund.bsi.tr_esor.vr.EvidenceRecordValidityType.ArchiveTimeStampSequence.ArchiveTimeStampChain;


/**
 * Wraps the results of an ATS sequence validation.
 *
 * @author BVO, TT
 */
public class ATSSequenceReport extends ReportPart implements OutputCreator<ArchiveTimeStampSequence>
{

    /**
     * Default validation results.
     */
    private final ArchiveTimeStampSequence xmlReport;

    /**
     * Creates instance.
     *
     * @param ref
     */
    public ATSSequenceReport(Reference ref)
    {
        super(ref);
        xmlReport = XmlHelper.FACTORY_ESOR_VR.createEvidenceRecordValidityTypeArchiveTimeStampSequence();
    }

    /**
     * Adds results to this report.
     *
     * @param report
     */
    public void addChild(ATSChainReport report)
    {
        updateCodes(report);
        xmlReport.getArchiveTimeStampChain().add(VRCreator.translate(report, ArchiveTimeStampChain.class));
    }

    @Override
    public ArchiveTimeStampSequence getFormatted()
    {
        return xmlReport;
    }

    @Override
    public Class<ArchiveTimeStampSequence> getTargetClass()
    {
        return ArchiveTimeStampSequence.class;
    }
}
