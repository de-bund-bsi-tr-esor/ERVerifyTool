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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.function.Function;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.NoVerificationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.VersionNotFoundException;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.validation.signatures.DetachedSignatureValidationContextBuilder;
import de.bund.bsi.tr_esor.checktool.validation.signatures.InlineSignatureValidationContext;
import de.bund.bsi.tr_esor.checktool.xml.LXaipDigestMismatchException;
import de.bund.bsi.tr_esor.checktool.xml.LXaipUnprocessableException;
import de.bund.bsi.tr_esor.checktool.xml.XaipReader;
import de.bund.bsi.tr_esor.xaip.CredentialType;
import de.bund.bsi.tr_esor.xaip.VersionManifestType;

import jakarta.xml.bind.JAXBException;


/**
 * Converts generic input (binary data, XAIP, ERs, CMS) into separate validation parameters for each evidence record.
 *
 * @author TT
 */
public class InputPreparator
{

    private static final Logger LOG = LoggerFactory.getLogger(InputPreparator.class);

    private final ParameterFinder params;

    List<ValidationContext<?>> validations = new ArrayList<>();

    /**
     * Sorts the input in case the XAIP has already been identified.
     */
    public InputPreparator(ParameterFinder params) throws ReflectiveOperationException, IOException {
        this.params = params;

        for (var erParameter : params.getProvidedERs())
        {
            if (isAoidOrVersionBroken(erParameter))
            {
                return;
            }
        }
        var xaip = params.getXaip();
        if (xaip != null)
        {
            scanXaipForEvidenceRecords();
            if (Configurator.getInstance().verifySignatures(params.getProfileName()))
            {
                scanXaipForInlineSignatures();
                scanXaipForDetachedSignatures();
            }
        }

        var cmsDocument = params.getCmsDocument();
        if (cmsDocument != null)
        {
            var reader = new CmsSignedDataReader(cmsDocument, params.getCmsRef());
            reader.getEmbeddedErs().forEach((r, v) -> createContextForErInCMS(r, v, reader));
        }

        if (xaip == null && cmsDocument == null)
        {
            for (var er : params.getProvidedERs())
            {
                createContextForDetachedEr(this::addProtectedDataFromBinaryDocuments, er);
            }
        }

        var unsupportedRef = params.getUnsupportedRef();
        if (unsupportedRef != null)
        {
            var message =
                params.getUnsupportedData() != null ? params.getUnsupportedData().getMessage() : "illegal or unsupported data format";
            var noVerificationContext = new NoVerificationContext(unsupportedRef, params.getProfileName(), message);
            validations.add(noVerificationContext);
        }
    }

    private ErValidationContext addProtectedDataFromBinaryDocuments(ErValidationContext evc)
    {
        var binaryDocuments = params.getBinaryDocuments();
        if (binaryDocuments.isEmpty())
        {
            if (params.getUnsupportedData() == null)
            {
                evc.addAdditionalMessage("No data found. The evidence record is not checked with regard to any data.");
            }
            else
            {
                evc.addAdditionalMessage("The input data uses an unsupported format. "
                    + params.getUnsupportedData().getMessage()
                    + " The evidence record is not checked with regard to the data.");
            }
        }
        else
        {
            binaryDocuments.forEach(evc::addProtectedData);
        }
        return evc;
    }

    private void scanXaipForEvidenceRecords() throws ReflectiveOperationException, IOException
    {
        var reader = new XaipReader(params.getXaip(), params.getXaipRef(), params.getProfileName());
        scanXaipForEmbeddedER(reader);
        for (var er : params.getProvidedERs()) {
            createContextForDetachedEr(ctx -> addProtectedElements(reader, er.getXaipVersionAddressedByEr(), ctx), er);
        }
    }

    private void scanXaipForInlineSignatures()
    {
        var reader = new XaipReader(params.getXaip(), params.getXaipRef(), params.getProfileName());
        var potentiallySigned = reader.findPotentiallyInlineSignedElements();
        for (var data : potentiallySigned)
        {
            var ctx = new InlineSignatureValidationContext(data, params.getProfileName());
            validations.add(ctx);
        }
    }

    private void scanXaipForDetachedSignatures() throws IOException
    {
        var reader = new XaipReader(params.getXaip(), params.getXaipRef(), params.getProfileName());
        var signatures = reader.findDetachedSignatures();
        for (var cred : signatures)
        {
            var ctx = new DetachedSignatureValidationContextBuilder().withProfileName(params.getProfileName())
                .withXaipSerializer(params.serializer)
                .withRestrictedValidation(params instanceof WSParameterFinder)
                .create(cred);
            validations.add(ctx);
        }
    }

    private void scanXaipForEmbeddedER(XaipReader reader) throws IOException, ReflectiveOperationException
    {
        for (var entry : reader.getEvidenceRecords().entrySet())
        {
            if (verifyReferencedVersionAndAoidForEvidenceRecord(entry, reader.getAoid()))
            {
                var er = entry.getValue().getEvidenceRecord();
                if (er.getVersionID() == null && reader.listVersions().size() > 1)
                {
                    createContextForNoVerification(entry.getKey(),
                        "There is more than one VersionManifest in the Xaip. The EvidenceRecord needs to specify which version it relates to. Possible versions are "
                            + reader.listVersions());
                    return;
                }

                if (er.getAsn1EvidenceRecord() == null)
                {
                    validations.add(new ErValidationContext(entry.getKey(), "no ASN.1 evidence record given", params.getProfileName()));
                }
                else
                {
                    var ctx = addProtectedElements(reader,
                        er.getVersionID(),
                        new ErValidationContext(entry.getKey(),
                            new ASN1EvidenceRecordParser().parse(er.getAsn1EvidenceRecord()),
                            params.getProfileName(),
                            params.getReturnVerificationReport(),
                            true));
                    validations.add(ctx);
                }
            }
        }
    }

    private boolean verifyReferencedVersionAndAoidForEvidenceRecord(Entry<Reference, CredentialType> credEntry, String aoid)
    {
        var cred = credEntry.getValue();

        var evidenceRecord = cred.getEvidenceRecord();
        if (evidenceRecord != null)
        {
            var aoidFromEr = evidenceRecord.getAOID();
            if (aoidFromEr != null && aoid != null && !aoidFromEr.equals(aoid))
            {
                createContextForNoVerification("AOID "
                    + aoid
                    + " in XAIP header does not match AOID "
                    + aoidFromEr
                    + " addressed in xaip:evidenceRecord.");
                return false;
            }
        }

        var relatedObjects = cred.getRelatedObjects();
        if (relatedObjects.isEmpty())
        {
            return true;
        }

        var numberOfVersionManifestsFound = 0;
        for (var o : relatedObjects)
        {
            if (!(o instanceof VersionManifestType))
            {
                continue;
            }

            numberOfVersionManifestsFound++;

            if (numberOfVersionManifestsFound > 1)
            {
                createContextForNoVerification(credEntry.getKey(), "An EvidenceRecord can only refer to one VersionManifest.");
                return false;
            }

            var versionID = ((VersionManifestType)o).getVersionID();
            if (cred.getEvidenceRecord().getVersionID() == null)
            {
                cred.getEvidenceRecord().setVersionID(versionID);
            }
            else if (!cred.getEvidenceRecord().getVersionID().equals(versionID))
            {
                createContextForNoVerification(credEntry.getKey(),
                    "Version ID for EvidenceRecord and relatedObjects reference in enveloping credential do not match");
                return false;
            }
        }

        if (numberOfVersionManifestsFound == 0)
        {
            createContextForNoVerification(credEntry.getKey(),
                "None of the relatedObjects of the given EvidenceRecord are referring to a VersionManifest.");
            return false;
        }
        return true;
    }

    /**
     * In case the evidence record has been specified inside an XML structure, asserts that a XAIP with specified AOID and version is
     * given.
     */
    private boolean isAoidOrVersionBroken(ERParameter erParameter)
    {
        var aoid = erParameter.getXaipAoidAddressedByEr();
        var version = erParameter.getXaipVersionAddressedByEr();
        if (version == null && aoid == null)
        {
            return false; // No restrictions to check
        }

        if (params.getXaip() == null)
        {
            createContextForNoVerification("Input specifies an evidence record for a XAIP but no XAIP is given.");
            return true;
        }
        var header = params.getXaip().getPackageHeader();
        if (header == null)
        {
            createContextForNoVerification("Given XAIP is not well-formed, thus requirements from xaip:evidenceRecord are not met.");
            return true;
        }

        if (aoid != null && !aoid.equals(header.getAOID()))
        {
            createContextForNoVerification("Given XAIP does not match AOID " + aoid + " addressed in xaip:evidenceRecord.");
            return true;
        }
        if (version != null && header.getVersionManifest().stream().noneMatch(m -> version.equals(m.getVersionID())))
        {
            createContextForNoVerification("Given XAIP does not contain version " + version + " addressed in xaip:evidenceRecord.");
            return true;
        }
        return false;
    }

    private void createContextForNoVerification(String message)
    {
        validations.add(new NoVerificationContext(params.getProfileName(), message));
    }

    private void createContextForNoVerification(Reference reference, String message)
    {
        validations.add(new NoVerificationContext(reference, params.getProfileName(), message));
    }

    private boolean needsToCheckAllHashes()
    {
        // For XAIPs all hashes in an ER need to be checked
        return params.getXaip() != null;
    }

    private void createContextForErInCMS(Reference ref, EvidenceRecord er, CmsSignedDataReader reader)
    {
        try
        {
            var ctx =
                new ErValidationContext(ref, er, params.getProfileName(), params.getReturnVerificationReport(), needsToCheckAllHashes());
            params.getBinaryDocuments().forEach(ctx::addProtectedData);
            ctx.addProtectedData(ref, reader.getContentInfoProtectedByEr(ref));
            validations.add(ctx);
        }
        catch (ReflectiveOperationException | IOException e)
        {
            throw new IllegalStateException("should not happen because config was checked at application start time", e);
        }
    }

    private ValidationContext<?> addProtectedElements(XaipReader reader, String version, ErValidationContext ctx)
    {
        var effectiveVersion = Optional.ofNullable(version).orElse(reader.getVersion());
        try
        {
            reader.prepareProtectedElements(effectiveVersion, params.getSerializer()).forEach(ctx::addProtectedData);
            return ctx;
        }
        catch (VersionNotFoundException e)
        {
            LOG.warn("Cannot find the secured data version referenced by the evidence record: {}", e.getMessage());
            return new NoVerificationContext(ctx.getReference(),
                ctx.getProfileName(),
                "Cannot find the secured data version referenced by the evidence record: " + e.getMessage(),
                e);
        }
        catch (JAXBException | XMLSecurityException | IOException e)
        {
            LOG.warn("Cannot get secured data, see Verification Report", e);
            return new NoVerificationContext(ctx.getReference(), "Cannot get secured data: " + e.getMessage(), ctx.getProfileName());
        }
        catch (LXaipDigestMismatchException e)
        {
            LOG.warn("Error processing LXAIP: {}", e.getMessage(), e);
            var report = ctx.getFormatOk();
            report.updateCodes(ValidationResultMajor.INVALID,
                "http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/hashValueMismatch",
                ReportPart.MinorPriority.MOST_IMPORTANT,
                e.getMessage(),
                new Reference(e.getDataObjectId()));
            ctx.disableCheckForAdditionalHashes();
            return ctx;
        }
        catch (LXaipUnprocessableException e)
        {
            LOG.warn("Error processing LXAIP: {}", e.getMessage(), e);
            var report = ctx.getFormatOk();
            var message = String.format("no protected data to check: %s", e.getMessage());
            report.updateCodes(ValidationResultMajor.INDETERMINED,
                "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError",
                ReportPart.MinorPriority.MOST_IMPORTANT,
                message,
                new Reference(e.getDataObjectId()));
            ctx.disableCheckForAdditionalHashes();
            return ctx;
        }
    }

    private void createContextForDetachedEr(Function<ErValidationContext, ValidationContext<?>> addProtectedData, ERParameter er)
        throws ReflectiveOperationException
    {
        if (er.getErRef() == null)
        {
            return;
        }
        if (er.getEr() == null)
        {
            validations.add(new ErValidationContext(er.getErRef(), "not an ASN.1 evidence record", params.getProfileName()));
        }
        else
        {
            var ctx = new ErValidationContext(er.getErRef(),
                er.getEr(),
                params.getProfileName(),
                params.getReturnVerificationReport(),
                needsToCheckAllHashes());
            validations.add(addProtectedData.apply(ctx));
        }
    }

    /**
     * Returns all the evidence records to validate together with the respective protected elements.
     */
    public List<ValidationContext<?>> getValidations()
    {
        return validations;
    }

}
