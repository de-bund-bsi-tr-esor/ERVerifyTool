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

import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.ArchiveTimeStampValidator;
import de.bund.bsi.tr_esor.checktool.validation.report.ArchiveTimeStampReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Basis-ERS-Profil requires the ArchiveTimeStamp not to contain the attributes tag.
 *
 * @author MO
 */
public class BasisErsArchiveTimeStampValidator extends ArchiveTimeStampValidator
{

  @Override
  protected ArchiveTimeStampReport validateInternal(Reference ref, ArchiveTimeStamp ats)
  {
    var report = super.validateInternal(ref, ats);
    if (ats.getAttributes() != null)
    {
      ctx.getFormatOk().invalidate("attributes must be omitted", ref.newChild("attributes"));
    }
    return report;
  }
}
