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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.bouncycastle.tsp.TimeStampToken;

import de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.data.DataGroup;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.AlgorithmValidityReport;
import de.bund.bsi.tr_esor.checktool.validation.report.ArchiveTimeStampReport;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ArchiveTimeStampValidityType.ReducedHashTree;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ArchiveTimeStampValidityType.ReducedHashTree.PartialHashTree;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.HashValueType;


/**
 * Validator for ArchiveTimeStamp objects.
 *
 * @author MO
 */
public class ArchiveTimeStampValidator
  extends BaseValidator<ArchiveTimeStamp, ErValidationContext, ArchiveTimeStampReport>
{

  /**
   * Taken from BSI TR-ESOR-VR V 1.2 p.10 + "Algo Mismatch" because no defined Minor covers that case.
   */
  private enum ValidationResultMinor
  {
    INVALID_FORMAT("http://www.bsi.bund.de/tr-esor/api/1.2/resultminor/invalidFormat"),
    HASH_VALUE_MISMATCH("http://www.bsi.bund.de/tr-esor/api/1.2/resultminor/hashValueMismatch"),
    SIGNATURE_FORMAT_NOT_SUITABLE("http://www.bsi.bund.de/ecard/api/1.1/resultminor//il/algorithm#signatureAlgorithmNotSuitable"),
    PARAMETER_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError"),
    SIGNATURE_FORMAT_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureFormatNotSupported"),
    SIGNATURE_ALGORITHM_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor//il/algorithm#signatureAlgorithmNotSupported"),
    UNKNOWN_ATTRIBUTE("http://www.bsi.bund.de/tr-esor/api/1.1/resultminor/unknownAttribute"),
    NOT_SUPPORTED("http://www.bsi.bund.de/tr-esor/api/1.2/resultminor/arl/notSupported");

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

  private ArchiveTimeStampReport atsReport;

  private FormatOkReport formatOk;

  private String hashOID;

  private Map<Reference, byte[]> requiredCoveredDigestValues;

  private String hashOIDInPrevATS;

  @Override
  protected ArchiveTimeStampReport validateInternal(Reference ref, ArchiveTimeStamp ats)
  {
    atsReport = new ArchiveTimeStampReport(ref);
    formatOk = new FormatOkReport(ref);
    Date secureDate = ctx.getSecureDate(ats);

    checkAscendingSecureDate(ats.getSignDateFromTimeStamp(), secureDate, ref);
    atsReport.addChild(checkDigestAlgorithm(ats, ref, secureDate));
    fillInReducedHashTree(ats);
    checkHashTree(ats);
    checkTimeStampToken(ref, ats.getTimeStampToken());
    atsReport.setFormatOk(formatOk);
    return atsReport;
  }

  /**
   * Digest algorithm must be checked individually for each ATS because same algorithm can be both suitable
   * and unsuitable as secured data changes.
   *
   * @param ats
   * @param secureDate
   */
  private AlgorithmValidityReport checkDigestAlgorithm(ArchiveTimeStamp ats, Reference ref, Date secureDate)
  {
    String oidFromTsp = ats.getOidFromTimeStamp();
    hashOID = oidFromTsp;
    ctx.setPossibleAlgorithmUsage(oidFromTsp, secureDate);
    Reference oidRef;

    if (ats.getDigestAlgorithm() == null)
    {
      oidRef = ref.newChild("tsp.messageImprintAlgOid");
    }
    else
    {
      String oidFromAtsAttribute = ats.getDigestAlgorithm().getAlgorithm().getId();
      oidRef = ref.newChild("attributeDigestAlgorithm");
      hashOID = oidFromAtsAttribute;
      if (!oidFromTsp.equals(oidFromAtsAttribute))
      {
        setInvalidFormat(formatOk,
                         ref,
                         "Algorithm attribute of ATS does not match the digest algorithm used in the TSP");
      }
    }

    if (!ctx.isAlgorithmDeclared(oidFromTsp))
    {
      setInvalidFormat(ctx.getFormatOk(), ref, "Digest algorithm not declared in evidence record/algorithms");
    }
    if (hashOIDInPrevATS != null && !hashOIDInPrevATS.equals(oidFromTsp))
    {
      setInvalidFormat(ctx.getFormatOk(),
                       ref,
                       "Digest algorithm does not match digest of previous ATs in same chain");
    }

    AlgorithmUsage usage = AlgorithmUsage.createHashed(hashOID, secureDate);
    return callValidator(usage,
                         oidRef,
                         null,
                         () -> new AlgorithmValidityReport(oidRef, oidFromTsp),
                         AlgorithmValidityReport.class);
  }

  /**
   * Check that the time stamp is older than it's secure date, this ensures that all time stamps are sorted in
   * ascending order.
   *
   * @param signDateFromTimeStamp
   * @param secureDate
   */
  private void checkAscendingSecureDate(Date signDateFromTimeStamp, Date secureDate, Reference ref)
  {
    if (!signDateFromTimeStamp.before(secureDate))
    {
      ctx.getFormatOk().invalidate(
                                   "The time of ArchiveTimeStamp is before the time of the previous ArchiveTimeStamp!",
                                   ref);
    }
  }

  private void setInvalidFormat(ReportPart target, Reference ref, String msg)
  {
    target.updateCodes(ValidationResultMajor.INVALID,
                       ValidationResultMinor.INVALID_FORMAT.toString(),
                       MinorPriority.IMPORTANT,
                       msg,
                       ref);
  }

  private void checkTimeStampToken(Reference atsID, TimeStampToken timeStampToken)
  {
    Reference tsp = atsID.newChild("tsp");
    atsReport.addChild(callValidator(timeStampToken, tsp, TimeStampReport.class));
  }

  /**
   * Sets all digest values which must be covered by this ATS in order to make it valid. Validation will fail
   * if all digest values are not completely found in the first partial hash tree (group) or in the TSP
   * itself.
   *
   * @param digests The digests for first ATS in chain, this contains the digest values of all protected
   *          elements and, if a previous chain exists, the digest of the ATS sequence up to the last chain.
   *          For subsequent ATS in a chain, this contains only the digest of the TSP of the previous ATS.
   *          Keys are free strings for debugging purposes only.
   * @param hashOIDInPreviousATS In case this ATS is not the first in chain, the algorithm specified here is
   *          used in the chain so far. Validation will fail if this ATS uses other digest algorithm in same
   *          chain.
   */
  void setDigestsToCover(Map<Reference, byte[]> digests, String hashOIDInPreviousATS)
  {
    requiredCoveredDigestValues = digests;
    this.hashOIDInPrevATS = hashOIDInPreviousATS;
  }

  /**
   * Asserts that required document hash(es) are found in the partial hash tree or tsp and that the partial
   * hash tree if exists is consistent.
   *
   * @param ats
   */
  private void checkHashTree(ArchiveTimeStamp ats)
  {
    List<byte[]> actuallyCoveredDigests = ats.numberOfPartialHashtrees() == 0
      ? Collections.singletonList(ats.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest())
      : ats.getPartialHashtree(0);

    checkProtectedElements(actuallyCoveredDigests);
    if (ats.numberOfPartialHashtrees() != 0)
    {
      checkHashes(ats);
    }
  }

  private void checkHashes(ArchiveTimeStamp ats)
  {
    byte[] timeStampMessageHash = ats.getTimeStampToken().getTimeStampInfo().getMessageImprintDigest();

    List<Function<DataGroup, byte[]>> hashFunctions = new ArrayList<>();
    hashFunctions.add(DataGroup::getHash);
    hashFunctions.add(DataGroup::getDoubleHash);

    for ( Function<DataGroup, byte[]> hashFunction : hashFunctions )
    {
      for ( boolean computeMissing : new boolean[]{true, false} )
      {
        byte[] lastGroupHash = getHashOfReducedHashTree(ats, hashFunction, hashOID, computeMissing);
        if (Arrays.equals(lastGroupHash, timeStampMessageHash))
        {
          return;
        }
      }
    }
    formatOk.updateCodes(ValidationResultMajor.INVALID,
                         ValidationResultMinor.HASH_VALUE_MISMATCH.toString(),
                         MinorPriority.MOST_IMPORTANT,
                         "hash tree root hash does not match timestamp",
                         atsReport.getReference().newChild("hashTree"));
  }

  private void fillInReducedHashTree(ArchiveTimeStamp ats)
  {
    // Attributes left out deliberately, because official dss-x schema type vr:AttributeType is insufficient
    // to carry useful information, as no OID can be specified.
    ReducedHashTree rht = XmlHelper.FACTORY_OASIS_VR.createArchiveTimeStampValidityTypeReducedHashTree();
    for ( int i = 0 ; i < ats.numberOfPartialHashtrees() ; i++ )
    {
      PartialHashTree pht = XmlHelper.FACTORY_OASIS_VR.createArchiveTimeStampValidityTypeReducedHashTreePartialHashTree();
      for ( byte[] v : ats.getPartialHashtree(i) )
      {
        HashValueType value = XmlHelper.FACTORY_OASIS_VR.createHashValueType();
        value.setHashValue(v);
        pht.getHashValue().add(value);
      }
      rht.getPartialHashTree().add(pht);
    }
    if (!rht.getPartialHashTree().isEmpty())
    {
      atsReport.getFormatted().setReducedHashTree(rht);
    }
  }

  private void checkProtectedElements(List<byte[]> atsHashes)
  {
    List<Reference> missingDigestIds = requiredCoveredDigestValues.entrySet()
                                                                  .stream()
                                                                  .filter(entry -> atsHashes.stream()
                                                                                             .noneMatch(hash -> Arrays.equals(hash,
                                                                                                                             entry.getValue())))
                                                                  .map(Entry::getKey)
                                                                  .collect(Collectors.toList());
    if (!missingDigestIds.isEmpty())
    {
      missingDigestIds.forEach(atsReport::addIdOfMissingHash);
      formatOk.updateCodes(ValidationResultMajor.INVALID,
                           ValidationResultMinor.HASH_VALUE_MISMATCH.toString(),
                           MinorPriority.MOST_IMPORTANT,
                           "Missing digest(s) for: " + missingDigestIds,
                           atsReport.getReference().newChild("protectedElements"));
    }
  }

  /**
   * Returns the root hash of a reduced hash tree. This method works both in the case that the computed hash
   * of one group must be added to the next group and in the case that it is already present in that group.
   *
   * @param ats
   * @param hashFunction Defines how to compute a hash value of a data group. This method can handle different
   *          cases of handling data groups with exactly one contained hash value.
   * @param digestOID specifies digest algorithm
   * @param handleHashesAsSet handles hashes in data groups as set (thus only considering one hash of multiple
   *          equal hashes for the group hash)
   */
  private byte[] getHashOfReducedHashTree(ArchiveTimeStamp ats,
                                          Function<DataGroup, byte[]> hashFunction,
                                          String digestOID,
                                          boolean handleHashesAsSet)
  {
    byte[] lastGroupsHash = null;
    for ( int i = 0 ; i < ats.numberOfPartialHashtrees() ; i++ )
    {
      DataGroup group = new DataGroup(ats.getPartialHashtree(i), digestOID);
      group.setHandleHashesAsSet(handleHashesAsSet);
      if (lastGroupsHash != null)
      {
        group.addHash(lastGroupsHash);
      }
      lastGroupsHash = hashFunction.apply(group);
    }
    return lastGroupsHash;
  }

  @Override
  protected Class<ErValidationContext> getRequiredContextClass()
  {
    return ErValidationContext.class;
  }
}
