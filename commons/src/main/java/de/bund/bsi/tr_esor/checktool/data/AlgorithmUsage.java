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

import java.util.Date;


/**
 * Wraps an algorithm OID combined with a date for which to check its validity.
 *
 * @author KK, TT
 */
public final class AlgorithmUsage
{

    private final String oid;

    private final Date validationDate;

    private final UsageType usage;

    /**
     * Creates immutable instance.
     *
     * @param oid
     * @param validationDate
     * @param usage
     */
    private AlgorithmUsage(String oid, Date validationDate, UsageType usage)
    {
        this.oid = oid;
        this.validationDate = (Date)validationDate.clone();
        this.usage = usage;
    }

    /**
     * Creates instance for a hash algorithm.
     *
     * @param oid
     * @param validationDate
     */
    public static AlgorithmUsage createHashed(String oid, Date validationDate)
    {
        return new AlgorithmUsage(oid, validationDate, UsageType.DATA_HASHING);
    }

    /**
     * Creates instance for a signature algorithm.
     *
     * @param oid
     * @param validationDate
     */
    public static AlgorithmUsage createSigned(String oid, Date validationDate)
    {
        return new AlgorithmUsage(oid, validationDate, UsageType.QES);
    }

    /**
     * Returns OID.
     */
    public String getOid()
    {
        return oid;
    }

    /**
     * Returns the data to check validity for.
     */
    public Date getValidationDate()
    {
        return (Date)validationDate.clone();
    }

    /**
     * Returns the usage type.
     */
    public UsageType getUsage()
    {
        return usage;
    }

    /**
     * Types of usage needed so far.
     */
    public enum UsageType
    {
        /** Hash algorithm */
        DATA_HASHING,

        /** Qualified signature algorithm (TSP) */
        QES
    }
}
