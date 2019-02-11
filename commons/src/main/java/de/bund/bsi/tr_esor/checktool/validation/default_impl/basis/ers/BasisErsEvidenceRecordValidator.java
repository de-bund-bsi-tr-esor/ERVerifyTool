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
package de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers;

import de.bund.bsi.tr_esor.checktool.data.CryptoInfo;
import de.bund.bsi.tr_esor.checktool.data.EncryptionInfo;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.EvidenceRecordValidator;
import de.bund.bsi.tr_esor.checktool.validation.report.EvidenceRecordReport;


/**
 * {@link EvidenceRecordValidator} which checks against Basis-ERS-Profil instead of RFC4998.
 *
 * @author HMA
 */
public class BasisErsEvidenceRecordValidator extends EvidenceRecordValidator
{

  @Override
  protected void checkVersion(int version, EvidenceRecordReport detailReport)
  {
    if (version != 1)
    {
      ctx.getFormatOk().invalidate("must be 1", detailReport.getReference().newChild("version"));
    }
  }

  @Override
  protected void checkCryptoInfo(CryptoInfo cryptoInfo, EvidenceRecordReport detailReport)
  {
    if (cryptoInfo != null)
    {
      ctx.getFormatOk().invalidate("must be omitted", detailReport.getReference().newChild("cryptoInfo"));
    }
  }

  @Override
  protected void checkEncryptionInfo(EncryptionInfo encryptionInfo, EvidenceRecordReport detailReport)
  {
    if (encryptionInfo != null)
    {
      ctx.getFormatOk().invalidate("must be omitted", detailReport.getReference().newChild("encryptionInfo"));
    }
  }
}
