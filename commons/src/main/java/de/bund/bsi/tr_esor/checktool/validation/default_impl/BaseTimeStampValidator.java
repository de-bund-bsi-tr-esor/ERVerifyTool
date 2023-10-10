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

import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.pkcs.SignedData;
import org.bouncycastle.tsp.TimeStampToken;

import de.bund.bsi.tr_esor.checktool.data.CAdESReader;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.ContentInfoChecker;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;


/**
 * Base class for basic time stamp validation.
 *
 * @author MO
 */
public abstract class BaseTimeStampValidator
  extends BaseValidator<TimeStampToken, ErValidationContext, TimeStampReport>
{

  protected byte[] sourceOfRootHash;

  /**
   * Checks the unsigned attributes of a time stamp for presence of certificate and revocation info.
   *
   * @param ts
   */
  protected void checkUnsignedAttributes(TimeStampToken ts, FormatOkReport formatOk)
  {
    var signedData = SignedData.getInstance(ContentInfo.getInstance(ts.toCMSSignedData().toASN1Structure())
                                                       .getContent());
    var requiredCMSVersion = ContentInfoChecker.SUPPORTED_CMS_VERSION;
    var reader = new CAdESReader(ts.toCMSSignedData());
    if (signedData.getCRLs() != null && signedData.getCRLs().size() != 0)
    {
      var choices = signedData.getCRLs().iterator();
      for ( var revCount = 0 ; choices.hasNext() ; revCount++ )
      {
        var ric = choices.next();
        Object asn1Object = ric instanceof ASN1TaggedObject ? ((ASN1TaggedObject)ric).getObject() : null;
        OtherRevocationInfoFormat orif = OtherRevocationInfoFormat.getInstance(asn1Object);

        if (orif != null)
        {
          requiredCMSVersion = ContentInfoChecker.SUPPORTED_CMS_VERSION_5;
          break;
        }
      }
    }
    if (!requiredCMSVersion.equals(signedData.getVersion()))
    {
      var message = String.format("Invalid CMS version %d in timestamp, the supported version is %d",
                                  signedData.getVersion().getValue().intValue(),
                                  requiredCMSVersion.getValue().intValue());
      formatOk.invalidate(message, formatOk.getReference());
    }
    if (!reader.hasCertificateValues()
        && (signedData.getCertificates() == null || signedData.getCertificates().size() == 0))
    {
      formatOk.invalidate("Missing certificates in time stamp", formatOk.getReference());
    }
    if (!reader.hasRevocationValues() && (signedData.getCRLs() == null || signedData.getCRLs().size() == 0))
    {
      formatOk.invalidate("Missing revocation info in time stamp", formatOk.getReference());
    }
  }

  @Override
  protected Class<ErValidationContext> getRequiredContextClass()
  {
    return ErValidationContext.class;
  }

  void setSourceOfRootHash(byte[] sourceOfRootHash)
  {
    this.sourceOfRootHash = sourceOfRootHash;
  }
}
