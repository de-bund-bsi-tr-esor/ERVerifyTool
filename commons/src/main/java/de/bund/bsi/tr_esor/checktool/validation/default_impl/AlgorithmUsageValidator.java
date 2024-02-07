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

import de.bund.bsi.tr_esor.checktool.conf.AlgorithmCatalog;
import de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage;
import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.Validator;
import de.bund.bsi.tr_esor.checktool.validation.report.AlgorithmValidityReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;


/**
 * Validates the suitability of an algorithm.
 *
 * @author KK, TT
 */
public class AlgorithmUsageValidator implements Validator<AlgorithmUsage, ValidationContext<?>, AlgorithmValidityReport>
{

    @Override
    public AlgorithmValidityReport validate(Reference ref, AlgorithmUsage toCheck)
    {
        var report = new AlgorithmValidityReport(ref, toCheck.getOid());
        var minor = check(toCheck);
        var major = minor == ValidationResultMinor.NULL ? ValidationResultMajor.VALID : ValidationResultMajor.INVALID;
        report.updateCodes(major, minor.toString(), MinorPriority.IMPORTANT, null, ref);
        return report;
    }

    /**
     * Checks if the given AlgorithmUsage is supported and suitable.
     *
     * @param algo
     * @return a feasible ValidationResultMinor
     */
    protected ValidationResultMinor check(AlgorithmUsage algo)
    {
        var catalog = AlgorithmCatalog.getInstance();
        var supportedAlgo = catalog.getSupportedAlgorithms().values().stream().filter(al -> al.getOids().contains(algo.getOid())).findAny();
        if (supportedAlgo.isPresent())
        {
            return supportedAlgo.get().getValidity().getTime() > algo.getValidationDate().getTime()
                ? ValidationResultMinor.NULL
                : ValidationResultMinor.HASH_ALGORITHM_NOT_SUITABLE;
        }
        return ValidationResultMinor.HASH_ALGORITHM_NOT_SUPPORTED;
    }

    @Override
    public void setContext(ValidationContext<?> context)
    {
        // this validator does not need any context.
    }

    /**
     * Minor codes for algorithm suitability.
     */
    protected enum ValidationResultMinor
    {

        /** Not suitable. */
        HASH_ALGORITHM_NOT_SUITABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/algorithm#hashAlgorithmNotSuitable"),
        /** Unknown. */
        HASH_ALGORITHM_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/algorithm#hashAlgorithmNotSupported"),
        /** Internal error. */
        INTERNAL_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError"),
        /** OK. */
        NULL(null);

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
