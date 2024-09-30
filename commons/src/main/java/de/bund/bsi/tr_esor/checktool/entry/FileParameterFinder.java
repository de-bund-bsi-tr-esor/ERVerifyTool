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

import static de.bund.bsi.tr_esor.checktool.xml.XmlHelper.FACTORY_OASIS_VR;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;

import org.bouncycastle.cms.CMSSignedData;

import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.data.UnsupportedData;
import de.bund.bsi.tr_esor.checktool.data.XaipAndSerializer;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ParserFactory;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.xaip.EvidenceRecordType;
import de.bund.bsi.tr_esor.xaip.XAIPType;


/**
 * Implementation of {@link ParameterFinder} for input as files.
 *
 * @author HMA, TT
 */
public class FileParameterFinder extends ParameterFinder
{

    /**
     * Creates an instance based on given files.
     *
     * @param protectedData should contain binary data, XAIP or CMS signature, last two possibly with contained ERs.
     * @param er optional, may be ASN.1 ER only or embedded into XML
     * @param profileName
     */
    public FileParameterFinder(Path protectedData, Path er, String profileName) throws IOException
    {
        super();
        handleProfileName(profileName);

        returnVerificationReport = FACTORY_OASIS_VR.createReturnVerificationReport();
        returnVerificationReport.setReportDetailLevel(ReportDetailLevel.ALL_DETAILS.toString());
        if (er != null)
        {
            setErAttributes(parse(er));
        }
        if (protectedData != null)
        {
            setDataAttribute(protectedData, parse(protectedData));
        }
    }

    private void setErAttributes(Object parsedEr) throws IOException
    {
        var baseErRef = new Reference("command line parameter er");
        var erParameter = new ERParameter();
        if (parsedEr instanceof EvidenceRecord)
        {
            erParameter.setEr((EvidenceRecord)parsedEr);
            erParameter.setErRef(baseErRef);
        }
        else if (parsedEr instanceof EvidenceRecordType)
        {
            var r = (EvidenceRecordType)parsedEr;
            erParameter.setXaipVersionAddressedByEr(r.getVersionID());
            erParameter.setXaipAoidAddressedByEr(r.getAOID());
            erParameter.setErRef(baseErRef.newChild("asn1EvidenceRecord"));
            erParameter.getErRef().setxPath("/evidenceRecord/asn1EvidenceRecord");
            if (r.getAsn1EvidenceRecord() != null)
            {
                erParameter.setEr(new ASN1EvidenceRecordParser().parse(r.getAsn1EvidenceRecord()));
            }
        }
        else if (parsedEr instanceof CMSSignedData)
        {
            cmsDocument = (CMSSignedData)parsedEr;
            cmsRef = baseErRef;
        }
        else if (parsedEr instanceof XAIPType) // anticipating a likely usage error
        {
            xaip = (XAIPType)parsedEr;
            xaipRef = baseErRef;
        }
        else
        {
            unsupportedRef = baseErRef;
        }
        providedERs.add(erParameter);
    }

    private void setDataAttribute(Path protectedData, Object parsedData) throws IOException
    {
        var dataRef = new Reference("command line parameter data");
        if (parsedData instanceof UnsupportedData)
        {
            unsupportedRef = dataRef;
            unsupportedData = (UnsupportedData)parsedData;
        }
        else if (parsedData instanceof XaipAndSerializer)
        {
            xaip = ((XaipAndSerializer)parsedData).getXaip();
            serializer = ((XaipAndSerializer)parsedData).getSerializer();
            xaipRef = dataRef;
        }
        else if (parsedData instanceof byte[])
        {
            binaryDocuments.put(dataRef, (byte[])parsedData);
        }
        else
        {
            try (InputStream ins = new FileInputStream(protectedData.toFile()))
            {
                binaryDocuments.put(dataRef, ins.readAllBytes());
            }
        }
    }

    private Object parse(Path path) throws IOException
    {
        try (InputStream fi = new FileInputStream(path.toFile());
            InputStream ins = new BufferedInputStream(fi))
        {
            return ParserFactory.parse(ins, getProfileName());
        }
        catch (IOException e)
        {
            throw new IOException("Cannot read content of file " + path.toAbsolutePath(), e);
        }
    }
}
