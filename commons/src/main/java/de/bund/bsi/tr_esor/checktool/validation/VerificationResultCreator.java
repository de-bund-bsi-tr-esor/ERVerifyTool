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
package de.bund.bsi.tr_esor.checktool.validation;

import oasis.names.tc.dss._1_0.core.schema.Result;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationResultType;

import de.bund.bsi.tr_esor.checktool.validation.report.OasisDssResultMajor;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;


/**
 * Creates results.
 *
 * @author KK, TT
 */
public final class VerificationResultCreator
{

    private VerificationResultCreator()
    {
        // static only
    }

    /**
     * Returns an OK result.
     */
    public static VerificationResultType createOK()
    {
        return create(ValidationResultMajor.VALID, null, null);
    }

    /**
     * Returns a result with specified codes and message.
     *
     * @param major
     * @param minor
     * @param message
     */
    public static VerificationResultType create(ValidationResultMajor major, String minor, String message)
    {
        var result = XmlHelper.FACTORY_OASIS_VR.createVerificationResultType();
        return getVerificationResultType(major, minor, message, result);
    }

    private static VerificationResultType getVerificationResultType(ValidationResultMajor major, String minor, String message,
        VerificationResultType result)
    {
        result.setResultMajor(major.toString());
        result.setResultMinor(minor);
        if (message != null)
        {
            var is = XmlHelper.FACTORY_DSS.createInternationalStringType();
            is.setLang("en");
            is.setValue(message);
            result.setResultMessage(is);
        }
        return result;
    }

    /**
     * Returns a result with specified codes and message.
     *
     * @param major
     * @param minor
     * @param message
     */
    public static Result createDssResult(OasisDssResultMajor major, String minor, String message)
    {
        var result = XmlHelper.FACTORY_DSS.createResult();
        result.setResultMajor(major.toString());
        result.setResultMinor(minor);
        if (message != null)
        {
            var is = XmlHelper.FACTORY_DSS.createInternationalStringType();
            is.setLang("en");
            is.setValue(message);
            result.setResultMessage(is);
        }
        return result;
    }

    /**
     * Returns a result with specified codes and message.
     */
    public static Result createECardResult(String major, String minor, String message)
    {
        var result = XmlHelper.FACTORY_DSS.createResult();
        result.setResultMajor(major);
        result.setResultMinor(minor);
        if (message != null)
        {
            var is = XmlHelper.FACTORY_DSS.createInternationalStringType();
            is.setLang("en");
            is.setValue(message);
            result.setResultMessage(is);
        }
        return result;
    }
}
