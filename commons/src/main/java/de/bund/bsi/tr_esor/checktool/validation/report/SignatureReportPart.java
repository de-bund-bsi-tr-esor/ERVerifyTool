/*-
 * Copyright (c) 2018
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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import jakarta.xml.bind.JAXBElement;
import oasis.names.tc.dss._1_0.core.schema.AnyType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.DetailedSignatureReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.IndividualReportType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.TimeStampValidityType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Report wrapper to allow later integration into the ERVerifyTool. No functionality except trivial stuff implemented yet.
 *
 * @author TT, WS
 */
public class SignatureReportPart extends ReportPart
{

    private VerificationReportType vr;

    /**
     * Creates instance.
     */
    public SignatureReportPart(Reference reference)
    {
        super(reference);
    }

    /**
     * Returns the wrapped report.
     */
    public VerificationReportType getVr()
    {
        return vr;
    }

    /**
     * Sets the wrapped report.
     */
    public void setVr(VerificationReportType vr)
    {
        this.vr = vr;
    }

    /**
     * Collects all {@link DetailedSignatureReportType} and {@link TimeStampValidityType} from all IndividualReports contained in provided
     * VerificationReportType.
     *
     * @return Map with {@link DetailedSignatureReportType} and {@link TimeStampValidityType} indexed by signature value
     */
    public Map<byte[], Object> findSignatureReportDetails()
    {
        var result = new LinkedHashMap<byte[], Object>();
        for (var individualReportType : vr.getIndividualReport())
        {
            var signatureValue = individualReportType.getSignedObjectIdentifier().getSignatureValue().getValue();
            for (var any : individualReportType.getDetails().getAny())
            {
                if (any instanceof JAXBElement<?>)
                {
                    var jaxbVal = ((JAXBElement<?>)any).getValue();
                    if (jaxbVal instanceof DetailedSignatureReportType || jaxbVal instanceof TimeStampValidityType)
                    {
                        result.put(signatureValue, jaxbVal);
                    }
                }
            }
        }
        return result;
    }

    @Override
    public boolean isDetailsPresent()
    {
        return Optional.ofNullable(vr)
            .map(VerificationReportType::getIndividualReport)
            .filter(l -> !l.isEmpty())
            .map(l -> l.get(0))
            .map(IndividualReportType::getDetails)
            .map(AnyType::getAny)
            .filter(l -> !l.isEmpty())
            .map(l -> l.get(0))
            .map(x -> ((JAXBElement<?>)x).getValue())
            .isPresent();
    }
}
