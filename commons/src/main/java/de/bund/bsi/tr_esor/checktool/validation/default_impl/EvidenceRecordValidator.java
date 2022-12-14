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

import de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampSequence;
import de.bund.bsi.tr_esor.checktool.data.CryptoInfo;
import de.bund.bsi.tr_esor.checktool.data.EncryptionInfo;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.report.ATSSequenceReport;
import de.bund.bsi.tr_esor.checktool.validation.report.AlgorithmValidityReport;
import de.bund.bsi.tr_esor.checktool.validation.report.EvidenceRecordReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Validator for evidence records.
 *
 * @author KK, TT
 */
public class EvidenceRecordValidator
  extends BaseValidator<EvidenceRecord, ErValidationContext, EvidenceRecordReport>
{

  private Reference reference;

  @Override
  public EvidenceRecordReport validateInternal(Reference ref, EvidenceRecord record)
  {
    if (!ctx.getReference().equals(ref))
    {
      throw new IllegalArgumentException("Reference does not match the context");
    }
    reference = ctx.getReference();

    var detailReport = new EvidenceRecordReport(ref);
    if (record == null)
    {
      ctx.getFormatOk().setNoParsedObject("Evidence record");
    }
    else
    {
      checkVersion(record.getVersion(), detailReport);
      checkCryptoInfo(record.getCryptoInfo(), detailReport);
      checkEncryptionInfo(record.getEncryptionInfo(), detailReport);
      ctx.setDeclaredDigestOIDs(record.getDigestAlgorithms());
      checkTimeStampSequence(record.getAtss(), detailReport);
      checkDigestAlgorithmValidity(record, detailReport);
    }
    detailReport.setFormatOk(ctx.getFormatOk());
    return detailReport;
  }

  /**
   * Checks version of evidence record.
   *
   * @param version
   * @param detailReport
   */
  protected void checkVersion(int version, EvidenceRecordReport detailReport)
  {
    if (version != 1)
    {
      ctx.getFormatOk().invalidate("unexpected version number", reference.newChild("version"));
    }
  }

  /**
   * Checks crypto info of evidence record.
   *
   * @param cryptoInfo
   * @param detailReport
   */
  protected void checkCryptoInfo(CryptoInfo cryptoInfo, EvidenceRecordReport detailReport)
  {
    // nothing to check for RFC4998
  }

  /**
   * Checks encryption info of evidence record.
   *
   * @param encryptionInfo
   * @param detailReport
   */
  protected void checkEncryptionInfo(EncryptionInfo encryptionInfo, EvidenceRecordReport detailReport)
  {
    // nothing to check for RFC4998
  }

  private void checkTimeStampSequence(ArchiveTimeStampSequence atss, EvidenceRecordReport detailReport)
  {
    var ref = reference.newChild("atss");
    detailReport.addChild(callValidator(atss, ref, ATSSequenceReport.class));
  }

  private void checkDigestAlgorithmValidity(EvidenceRecord record, EvidenceRecordReport detailReport)
  {
    for ( var oid : record.getDigestAlgorithms() )
    {
      var usage = AlgorithmUsage.createHashed(oid, ctx.getLatestPossibleUsage(oid));

      var ref = reference.newChild("digestAlgorithms:" + oid);
      detailReport.addChild(callValidator(usage,
                                          ref,
                                          null,
                                          () -> new AlgorithmValidityReport(ref, oid),
                                          AlgorithmValidityReport.class));
    }
  }

  @Override
  protected Class<ErValidationContext> getRequiredContextClass()
  {
    return ErValidationContext.class;
  }

}
