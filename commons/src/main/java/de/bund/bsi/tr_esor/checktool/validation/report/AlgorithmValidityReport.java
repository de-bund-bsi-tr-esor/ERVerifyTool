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

import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.AlgorithmValidityType;


/**
 * Wraps an AlgorithmValidityType.
 *
 * @author HMA, TT
 */
public class AlgorithmValidityReport extends ReportPart implements OutputCreator<AlgorithmValidityType>
{

    private final AlgorithmValidityType xmlReport;

    /**
     * Creates a new instance.
     *
     * @param reference
     */
    public AlgorithmValidityReport(Reference reference, String oid)
    {
        super(reference);
        xmlReport = XmlHelper.FACTORY_OASIS_VR.createAlgorithmValidityType();
        xmlReport.setAlgorithm(oid);
    }

    @Override
    public AlgorithmValidityType getFormatted()
    {
        xmlReport.setSuitability(getOverallResult());
        return xmlReport;
    }

    @Override
    public Class<AlgorithmValidityType> getTargetClass()
    {
        return AlgorithmValidityType.class;
    }

}
