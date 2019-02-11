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

/**
 * Enum for ReportDetailLevel of ReturnVerificationReport.
 *
 * @author BVO
 */
public enum ReportDetailLevel
{

  /** Only the final result. */
  NO_DETAILS("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:reportdetail:noDetails"),

  /** ReportDetailLevel for no path details. */
  NO_PATH_DETAILS("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:reportdetail:noPathDetails"),

  /** ReportDetailLevel for all details. (default) */
  ALL_DETAILS("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:reportdetail:allDetails");

  private final String value;

  ReportDetailLevel(String value)
  {
    this.value = value;
  }

  @Override
  public String toString()
  {
    return value;
  }
}
