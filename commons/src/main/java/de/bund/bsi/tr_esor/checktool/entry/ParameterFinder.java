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
package de.bund.bsi.tr_esor.checktool.entry;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;

import org.bouncycastle.cms.CMSSignedData;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.data.UnsupportedData;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.XaipSerializer;
import de.bund.bsi.tr_esor.xaip.XAIPType;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;


/**
 * Finds evidence records and documents to check. This class supports one XAIP or CMS signed data, possibly with embedded ERs, an arbitrary
 * number of binary documents, one detached evidence record (request allows only one signed object).
 *
 * @author TT
 */
public abstract class ParameterFinder
{

    /**
     * binary documents given as input (CMS and XAIP not listed here).
     */
    protected final Map<Reference, byte[]> binaryDocuments = new HashMap<>();

    /** CMS signed data (possibly with ERs contained) specified in input */
    protected CMSSignedData cmsDocument;

    /** XAIP (possibly with ERs contained) specified in input */
    protected XAIPType xaip;

    /** serializer for XAIP elements */
    protected XaipSerializer serializer;

    /** where that element came from */
    protected Reference xaipRef;

    /** List of all provided er **/
    protected List<ERParameter> providedERs = new ArrayList<>();

    /** where that element came from */
    protected Reference cmsRef;

    /** reference of some input which cannot be parsed to any supported type. */
    protected Reference unsupportedRef;

    /** Information on the input in the unsupported ref. */
    protected UnsupportedData unsupportedData;

    /** returnVerificationReport specified in the optionalinputs. **/
    protected ReturnVerificationReport returnVerificationReport;

    private String profileName;

    /**
     * Returns the ReturnVerificationReport.
     */
    public ReturnVerificationReport getReturnVerificationReport()
    {
        return returnVerificationReport;
    }

    /**
     * Returns the binary documents addressed by some unique id.
     */
    public Map<Reference, byte[]> getBinaryDocuments()
    {
        return binaryDocuments;
    }

    /**
     * Returns the given CMS signed data.
     */
    public CMSSignedData getCmsDocument()
    {
        return cmsDocument;
    }

    /**
     * Returns the XAIP specified as input.
     */
    public XAIPType getXaip()
    {
        return xaip;
    }

    /**
     * Returns the Serializer for the Xaip
     */
    public XaipSerializer getSerializer()
    {
        return serializer;
    }

    /**
     * Returns profile name from request or configured default one if none was specified.
     */
    public String getProfileName()
    {
        return profileName;
    }

    /**
     * Returns the reference the XAIP came from.
     */
    public Reference getXaipRef()
    {
        return xaipRef;
    }

    /**
     * Returns a list of all Evidence Records provided by the verify request.
     */
    public List<ERParameter> getProvidedERs()
    {
        return providedERs;
    }

    /**
     * Returns the reference the CMS signature came from.
     */
    public Reference getCmsRef()
    {
        return cmsRef;
    }

    /**
     * Returns a reference of an input element which cannot be parsed into any supported format.
     */
    public Reference getUnsupportedRef()
    {
        return unsupportedRef;
    }

    /**
     * Returns information on the unsupported element referenced through the unsupportedRef
     */
    public UnsupportedData getUnsupportedData()
    {
        return unsupportedData;
    }

    /**
     * Sets the profile name attribute to given or configured default value.
     *
     * @param byRequest
     */
    protected void handleProfileName(String byRequest)
    {
        profileName = Optional.ofNullable(Optional.ofNullable(byRequest).orElse(Configurator.getInstance().getDefaultProfileName()))
            .orElse(ProfileNames.RFC4998);
    }
}
