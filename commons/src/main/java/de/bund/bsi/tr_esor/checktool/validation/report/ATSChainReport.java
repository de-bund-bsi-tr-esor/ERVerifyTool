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
import de.bund.bsi.tr_esor.vr.EvidenceRecordValidityType.ArchiveTimeStampSequence.ArchiveTimeStampChain;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ArchiveTimeStampValidityType;


/**
 * Wraps the findings of an ATS chain validation.
 *
 * @author BVO, TT
 */
public class ATSChainReport extends ReportPart implements OutputCreator<ArchiveTimeStampChain>
{

    /**
     * Default validation results. Note that special validator implementations may produce data which does not fit that schema.
     */
    private final ArchiveTimeStampChain xmlReport;

    /**
     * Creates instance.
     *
     * @param ref position inside the ATSSequence
     */
    public ATSChainReport(Reference ref)
    {
        super(ref);
        xmlReport = XmlHelper.FACTORY_ESOR_VR.createEvidenceRecordValidityTypeArchiveTimeStampSequenceArchiveTimeStampChain();
    }

    @Override
    public ArchiveTimeStampChain getFormatted()
    {
        return xmlReport;
    }

    @Override
    public Class<ArchiveTimeStampChain> getTargetClass()
    {
        return ArchiveTimeStampChain.class;
    }

    /**
     * Adds results to this report.
     *
     * @param report
     */
    public void addChild(ArchiveTimeStampReport report)
    {
        updateCodes(report);
        xmlReport.getArchiveTimeStamp().add(VRCreator.translate(report, ArchiveTimeStampValidityType.class));
    }

}
