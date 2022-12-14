/*-
 * Copyright (c) 2018
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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import oasis.names.tc.dss._1_0.core.schema.SignatureObject;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ObjectFactory;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;

import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.XaipSerializer;


/**
 * Context for validation of a detached signature found in a credential object inside a XAIP.
 *
 * @author TT, WS
 */
public class DetachedSignatureValidationContext extends ValidationContext<SignatureObject>
{

  private final Map<Reference, byte[]> protectedDataByID;

  private final Map<Reference, String> preferredExtension = new HashMap<>();

  private XaipSerializer serializer;

  protected boolean restrictedValidation;

  /**
   * Creates an instance
   */
  public DetachedSignatureValidationContext(Reference reference,
                                            SignatureObject objectToValidate,
                                            Map<Reference, byte[]> protectedDataByID,
                                            String profileName)
  {
    super(reference, objectToValidate, profileName, getAllDetailsRVR());
    this.protectedDataByID = protectedDataByID;
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

  /**
   * Defines a file extension in case the protected data shall be written into a file.
   *
   * @param ref specifies which data object is meant
   */
  public void setPreferredExtension(Reference ref, String extension)
  {
    if (!protectedDataByID.containsKey(ref))
    {
      throw new IllegalArgumentException("Not a reference of protected data: " + ref);
    }
    preferredExtension.put(ref, extension);
  }

  /**
   * Sets several preferred extensions.
   *
   * @return reference to this to allow fluent API
   */
  public DetachedSignatureValidationContext withPreferredExtensions(Map<Reference, String> extensionByRef)
  {
    extensionByRef.forEach(this::setPreferredExtension);
    return this;
  }

  /**
   * Returns the extension to use when writing a protected data into a file.
   */
  public String getPreferredExtension(Reference ref)
  {
    return preferredExtension.getOrDefault(ref, ".xml");
  }

  @Override
  public Class<SignatureObject> getTargetClass()
  {
    return SignatureObject.class;
  }

  /**
   * Returns the data protected by the signature.
   */
  public Map<Reference, byte[]> getProtectedDataByID()
  {
    return Collections.unmodifiableMap(protectedDataByID);
  }

  /**
   * Returns an XML serializer which is able to restore the original name space prefix and non-element nodes
   * as found in the request. Note that JAXB objects are not able to preserve namespace prefixes.
   */
  public XaipSerializer getSerializer()
  {
    return serializer;
  }

  /**
   * Sets the serializer which knows the name space prefixes from original data.
   */
  public DetachedSignatureValidationContext withSerializer(XaipSerializer value)
  {
    serializer = value;
    return this;
  }

  /**
   * Set to <code>true</code> if some validations cannot be done in given context
   *
   * @return this (fluid api)
   */
  public DetachedSignatureValidationContext withRestrictedValidation(boolean value)
  {
    this.restrictedValidation = value;
    return this;
  }

  @Override
  public boolean isRestrictedValidation()
  {
    return restrictedValidation;
  }
}
