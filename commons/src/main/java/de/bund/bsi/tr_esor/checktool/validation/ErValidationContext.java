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
package de.bund.bsi.tr_esor.checktool.validation;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;

import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.hash.HashCreator;
import de.bund.bsi.tr_esor.checktool.validation.report.FormatOkReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;



/**
 * Wrapper for data collected while validating a single evidence record.
 *
 * @author TT
 */
public class ErValidationContext extends ValidationContext<EvidenceRecord>
{

  private final Map<Reference, byte[]> protectedDataByID = new HashMap<>();

  private List<String> declaredDigestOIDs;

  private HashCreator hashCreator;

  private final String parseFailMessage;

  private final FormatOkReport formatOk;

  /**
   * Key is algorithm OID, value is secured date of latest usage.
   */
  private final Map<String, Date> latestUsage = new HashMap<>();

  /**
   * Key is ATS in evidence record, value is time when the ATS was secured by another ATS or now for the last
   * one.
   */
  private final Map<ArchiveTimeStamp, Date> securedByDate = new IdentityHashMap<>();

  /**
   * Creates instance for a successfully parsed evidence record.
   *
   * @param reference
   * @param objectToValidate
   * @param profileName
   * @param returnVerificationReport
   * @throws ReflectiveOperationException
   */
  public ErValidationContext(Reference reference,
                             EvidenceRecord objectToValidate,
                             String profileName,
                             ReturnVerificationReport returnVerificationReport)
    throws ReflectiveOperationException
  {
    super(reference, objectToValidate, profileName, returnVerificationReport);
    this.hashCreator = ValidatorFactory.getInstance().getHashCreator();
    this.parseFailMessage = null;
    this.formatOk = new FormatOkReport(reference);
  }

  /**
   * Creates instance in case the evidence record cannot be parsed.
   *
   * @param reference
   * @param parseFailMessage
   * @param profileName
   */
  public ErValidationContext(Reference reference, String parseFailMessage, String profileName)
  {
    super(reference, null, profileName, null);
    this.parseFailMessage = parseFailMessage;
    this.formatOk = null;
  }

  /**
   * Adds protected data so that the hash is checked in the evidence record.
   *
   * @param key
   * @param data
   */
  public void addProtectedData(Reference key, byte[] data)
  {
    if (protectedDataByID.containsKey(key))
    {
      throw new IllegalArgumentException("duplicate key: " + key);
    }
    protectedDataByID.put(key, data);
  }


  /**
   * Returns a map of digests of all protected data by a unique ID which can be used to report a missing
   * digest.
   *
   * @param digestOID
   * @throws NoSuchAlgorithmException
   */
  public Map<Reference, byte[]> getRequiredDigests(String digestOID) throws NoSuchAlgorithmException
  {
    Map<Reference, byte[]> result = new HashMap<>();
    for ( Entry<Reference, byte[]> entry : protectedDataByID.entrySet() )
    {
      result.put(entry.getKey(), hashCreator.calculateHash(entry.getValue(), digestOID));
    }
    return result;
  }

  /**
   * Returns <code>true</code> if a specified digest has been declared in the algorithms section of the
   * evidence record.
   *
   * @param digestOID
   */
  public boolean isAlgorithmDeclared(String digestOID)
  {
    return declaredDigestOIDs.contains(digestOID);
  }

  /**
   * Returns a time after which the given algorithm is definitely not used in the ER.
   *
   * @param algoOID
   */
  public Date getLatestPossibleUsage(String algoOID)
  {
    return Optional.ofNullable(latestUsage.get(algoOID)).orElse(new Date());
  }

  /**
   * Specifies a time after which the given algorithm is definitely not used in the ER.
   *
   * @param algoOID
   * @param possibleUsage
   */
  public void setPossibleAlgorithmUsage(String algoOID, Date possibleUsage)
  {
    Date known = latestUsage.get(algoOID);
    if (known == null || known.after(possibleUsage))
    {
      latestUsage.put(algoOID, possibleUsage);
    }
  }

  @Override
  public Class<EvidenceRecord> getTargetClass()
  {
    return EvidenceRecord.class;
  }

  /**
   * Returns a message describing why parsing the evidence record failed.
   */
  public String getParseFailMessage()
  {
    return parseFailMessage;
  }

  /**
   * Returns the formatOk result which must possibly be updated by different validators. Unfortunately, the
   * XML verification report does not provide fields for certain problems in ATS, ATS chains and so on but
   * uses the overall formatOk field for that purpose.
   */
  public FormatOkReport getFormatOk()
  {
    return formatOk;
  }

  /**
   * Defines which digest algorithms are specified in the evidence record.
   *
   * @param declaredDigestOIDs
   */
  public void setDeclaredDigestOIDs(List<String> declaredDigestOIDs)
  {
    this.declaredDigestOIDs = declaredDigestOIDs;
  }

  /**
   * Returns the time when the given ATS was secured.
   *
   * @param ats
   */
  public Date getSecureDate(ArchiveTimeStamp ats)
  {
    return securedByDate.get(ats);
  }

  /**
   * Sets the given secure time for the given ATS.
   *
   * @param ats
   * @param date
   */
  public void setSecureData(ArchiveTimeStamp ats, Date date)
  {
    securedByDate.put(ats, date);
  }
}
