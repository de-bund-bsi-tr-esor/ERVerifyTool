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

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampChain;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.ATSChainReport;
import de.bund.bsi.tr_esor.checktool.validation.report.ArchiveTimeStampReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart.MinorPriority;


/**
 * Validator for ArchiveTimeStampChain objects.
 *
 * @author TT, MO
 */
public class ArchiveTimeStampChainValidator
  extends BaseValidator<ArchiveTimeStampChain, ErValidationContext, ATSChainReport>
{

  private static final Logger LOG = LoggerFactory.getLogger(ArchiveTimeStampChainValidator.class);

  private ATSChainReport report;

  private byte[] prevChainHash;

  @Override
  protected ATSChainReport validateInternal(Reference ref, ArchiveTimeStampChain toCheck)
  {
    report = new ATSChainReport(ref);
    if (toCheck.isEmpty())
    {
      return report;
    }
    Map<Reference, byte[]> digestsToCover = new HashMap<>();
    String digestOid = toCheck.get(0).getOidFromTimeStamp();

    try
    {
      if (prevChainHash == null)
      {
        digestsToCover.putAll(ctx.getRequiredDigests(digestOid));
      }
      else
      {
        addHashedConcatenation(ref, digestsToCover, digestOid);
      }
      if (digestsToCover.isEmpty())
      {
        report.updateCodes(ValidationResultMajor.INDETERMINED,
                           "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError",
                           MinorPriority.MOST_IMPORTANT,
                           "no protected data to check",
                           ref);
      }
    }
    catch (NoSuchAlgorithmException e)
    {
      LOG.debug("unsupported algorithm", e);
      report.updateCodes(ValidationResultMajor.INDETERMINED,
                         "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError",
                         MinorPriority.MOST_IMPORTANT,
                         "unsupported digest oid: " + digestOid,
                         ref);
      return report;
    }

    for ( int i = 0 ; i < toCheck.size() ; i++ )
    {
      ArchiveTimeStamp ats = toCheck.get(i);
      Reference atsRef = ref.newChild(Integer.toString(i));
      report.addChild(callValidator(ats,
                                    atsRef,
                                    val -> ((ArchiveTimeStampValidator)val).setDigestsToCover(digestsToCover,
                                                                                              digestOid),
                                    ArchiveTimeStampReport.class));
      digestsToCover.clear();
      digestsToCover.put(new Reference("prev TSP of chain"),
                         computeHash(ats::getContentOfTimeStampField, digestOid, atsRef, report));
    }
    return report;
  }

  private void addHashedConcatenation(Reference id, Map<Reference, byte[]> digestsToCover, String digestOid)
    throws NoSuchAlgorithmException
  {
    for ( Entry<Reference, byte[]> digestEntry : ctx.getRequiredDigests(digestOid).entrySet() )
    {
      byte[] concatHash = new byte[prevChainHash.length * 2];
      System.arraycopy(digestEntry.getValue(), 0, concatHash, 0, prevChainHash.length);
      System.arraycopy(prevChainHash, 0, concatHash, prevChainHash.length, prevChainHash.length);
      digestsToCover.put(digestEntry.getKey(), computeHash(() -> concatHash, digestOid, id, report));
    }
  }

  /**
   * Sets the hash of previous ATS chains, if existing.
   *
   * @param prevChainHash
   */
  void setPrevChainHash(byte[] prevChainHash)
  {
    this.prevChainHash = prevChainHash;
  }

  @Override
  protected Class<ErValidationContext> getRequiredContextClass()
  {
    return ErValidationContext.class;
  }
}
