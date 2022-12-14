/*-
 * Copyright (c) 2019
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
package de.bund.bsi.tr_esor.checktool.validation.signatures;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ObjectFactory;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;

import de.bund.bsi.tr_esor.checktool.data.InlineSignedData;
import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;


/**
 * Context for validation of embedded data object signature inside a XAIP.
 *
 * @author PRE
 */
public class InlineSignatureValidationContext extends ValidationContext<InlineSignedData>
{

  /**
   * Default constructor.
   *
   * @param objectToValidate DataObject containing an inline signature
   */
  public InlineSignatureValidationContext(InlineSignedData objectToValidate, String profileName)
  {
    super(objectToValidate.getReference(), objectToValidate, profileName, getAllDetailsRVR());
  }

  private static ReturnVerificationReport getAllDetailsRVR()
  {
    ReturnVerificationReport rvr = new ObjectFactory().createReturnVerificationReport();
    rvr.setIncludeVerifier(Boolean.TRUE);
    rvr.setIncludeCertificateValues(Boolean.TRUE);
    rvr.setIncludeRevocationValues(Boolean.TRUE);
    rvr.setExpandBinaryValues(Boolean.TRUE);
    rvr.setReportDetailLevel("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:reportdetail:allDetails");
    return rvr;
  }

  @Override
  public Class<InlineSignedData> getTargetClass()
  {
    return InlineSignedData.class;
  }

  @Override
  public boolean isRestrictedValidation()
  {
    return false;
  }

}
