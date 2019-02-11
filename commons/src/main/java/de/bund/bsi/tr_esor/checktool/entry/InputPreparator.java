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
import java.util.function.Consumer;

import javax.xml.bind.JAXBException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.NoVerificationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.XaipReader;
import de.bund.bsi.tr_esor.xaip._1.CredentialType;
import de.bund.bsi.tr_esor.xaip._1.EvidenceRecordType;
import de.bund.bsi.tr_esor.xaip._1.PackageHeaderType;
import de.bund.bsi.tr_esor.xaip._1.VersionManifestType;


/**
 * Converts generic input (binary data, XAIP, ERs, CMS) into separate validation parameters for each evidence
 * record.
 *
 * @author TT
 */
public class InputPreparator
{

  private static final Logger LOG = LoggerFactory.getLogger(InputPreparator.class);

  List<ValidationContext<?>> validations = new ArrayList<>();

  private final ParameterFinder params;

  /**
   * Sorts the input in case the XAIP has already been identified.
   *
   * @param params
   * @throws IOException
   * @throws ReflectiveOperationException
   */
  public InputPreparator(ParameterFinder params) throws ReflectiveOperationException, IOException
  {
    this.params = params;

    if (isAoidOrVersionBroken())
    {
      return;
    }
    else if (params.getXaip() != null)
    {
      XaipReader reader = new XaipReader(params.getXaip(), params.getXaipRef());
      for ( Entry<Reference, CredentialType> entry : reader.getEvidenceRecords().entrySet() )
      {
        if (checkRelatedObjectsVersionId(entry.getValue()))
        {
          EvidenceRecordType er = entry.getValue().getEvidenceRecord();
          if (er.getAsn1EvidenceRecord() == null)
          {
            validations.add(new ErValidationContext(entry.getKey(), "no ASN.1 evidence record given",
                                                    params.getProfileName()));
          }
          else
          {
            ErValidationContext ctx = new ErValidationContext(entry.getKey(),
                                                              new ASN1EvidenceRecordParser().parse(er.getAsn1EvidenceRecord()),
                                                              params.getProfileName(),
                                                              params.getReturnVerificationReport());
            addProtectedElements(reader, er.getVersionID(), ctx);
            validations.add(ctx);
          }
        }
        else
        {
          createContextForNoVerification(entry.getKey(),
                                         "Version ID for EvidenceRecord and relatedObjects reference in enveloping credential do not match");
        }
      }
      createContextForDetachedEr(ctx -> addProtectedElements(reader,
                                                             params.getXaipVersionAddressedByEr(),
                                                             ctx));
    }
    else if (params.getCmsDocument() != null)
    {
      CmsSignedDataReader reader = new CmsSignedDataReader(params.getCmsDocument(), params.getCmsRef());
      reader.getEmbeddedErs().forEach((r, v) -> createContextForErInCMS(r, v, reader));
    }
    else
    {
      createContextForDetachedEr(ctx -> params.getBinaryDocuments().forEach(ctx::addProtectedData));
    }

    if (params.getUnsupportedRef() != null)
    {
      validations.add(ValidationContext.forUnsupported(params.getUnsupportedRef(), params.getProfileName()));
    }
  }


  private boolean checkRelatedObjectsVersionId(CredentialType cred)
  {
    List<Object> relatedObjects = cred.getRelatedObjects();
    for ( Object o : relatedObjects )
    {
      if (o instanceof VersionManifestType)
      {
        String versionID = ((VersionManifestType)o).getVersionID();
        if (cred.getEvidenceRecord().getVersionID() == null)
        {
          cred.getEvidenceRecord().setVersionID(versionID);
        }
        else if (!cred.getEvidenceRecord().getVersionID().equals(versionID))
        {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * In case the evidence record has been specified inside an XML structure, asserts that a XAIP with
   * specified AOID and version is given.
   */
  private boolean isAoidOrVersionBroken()
  {
    String aoid = params.getXaipAoidAddressedByEr();
    String version = params.getXaipVersionAddressedByEr();
    if (version == null && aoid == null)
    {
      return false; // No restrictions to check
    }

    if (params.getXaip() == null)
    {
      createContextForNoVerification("Input specifies an evidence record for a XAIP but no XAIP is given.");
      return true;
    }
    PackageHeaderType header = params.getXaip().getPackageHeader();
    if (header == null)
    {
      createContextForNoVerification("Given XAIP is not well-formed, thus requirements from xaip:evidenceRecord are not met.");
      return true;
    }
    if (aoid != null && !aoid.equals(header.getAOID()))
    {
      createContextForNoVerification("Given XAIP does not match AOID " + aoid
                                     + " addressed in xaip:evidenceRecord.");
      return true;
    }
    if (version != null
        && header.getVersionManifest().stream().noneMatch(m -> version.equals(m.getVersionID())))
    {
      createContextForNoVerification("Given XAIP does not contain version " + version
                                     + " addressed in xaip:evidenceRecord.");
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

  private void createContextForErInCMS(Reference ref, EvidenceRecord er, CmsSignedDataReader reader)
  {
    try
    {
      ErValidationContext ctx = new ErValidationContext(ref, er, params.getProfileName(),
                                                        params.getReturnVerificationReport());
      params.getBinaryDocuments().forEach(ctx::addProtectedData);
      ctx.addProtectedData(ref, reader.getContentInfoProtectedByEr(ref));
      validations.add(ctx);
    }
    catch (ReflectiveOperationException | IOException e)
    {
      throw new IllegalStateException("should not happen because config was checked at application start time",
                                      e);
    }
  }

  private ErValidationContext addProtectedElements(XaipReader reader, String version, ErValidationContext val)
  {
    String effectiveVersion = Optional.ofNullable(version).orElse(reader.getVersion());
    try
    {
      reader.getProtectedElements(effectiveVersion).forEach(val::addProtectedData);
      return val;
    }
    catch (JAXBException | XMLSecurityException e)
    {
      LOG.error("Cannot get secured data", e);
      return new ErValidationContext(val.getReference(), "Cannot get secured data: " + e.getMessage(),
                                     val.getProfileName());
    }
  }

  private void createContextForDetachedEr(Consumer<ErValidationContext> addProctedData)
    throws ReflectiveOperationException
  {
    if (params.getErRef() == null)
    {
      return;
    }
    if (params.getEr() == null)
    {
      validations.add(new ErValidationContext(params.getErRef(), "not an ASN.1 evidence record",
                                              params.getProfileName()));
    }
    else
    {
      ErValidationContext ctx = new ErValidationContext(params.getErRef(), params.getEr(),
                                                        params.getProfileName(),
                                                        params.getReturnVerificationReport());
      addProctedData.accept(ctx);
      validations.add(ctx);
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
