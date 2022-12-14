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



/**
 * 3 kinds of validation verdict: valid, invalid, inconclusive.
 *
 * @author HMA, TT
 */
public enum ValidationResultMajor
{

  /**
   * The result of the validation is valid.
   */
  VALID("valid"),

  /**
   * The result of the validation is inconclusive.
   */
  INDETERMINED("indetermined"),

  /**
   * The result of the validation is invalid.
   */
  INVALID("invalid");

  private String value;

  ValidationResultMajor(String value)
  {
    this.value = "urn:oasis:names:tc:dss:1.0:detail:" + value;
  }

  @Override
  public String toString()
  {
    return value;
  }

  /**
   * Returns the "less valid" value.
   */
  public ValidationResultMajor worse(ValidationResultMajor other)
  {
    var effectiveOther = other == null ? INDETERMINED : other;
    return compareTo(effectiveOther) > 0 ? this : effectiveOther;
  }

  /**
   * Returns matching instance (prefix ignored).
   *
   * @param value
   */
  public static ValidationResultMajor forValue(String value)
  {
    for ( var m : values() )
    {
      if (m.value.equals(value))
      {
        return m;
      }
    }
    return null;
  }

  /**
   * Returns matching instance, takes an DSS result as specified in the "OASIS DSS core specification v1.0".
   */
  public static ValidationResultMajor forDssResult(String major, String minor)
  {
    if ("urn:oasis:names:tc:dss:1.0:resultmajor:Success".equals(major)
        && "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments".equals(minor))
    {
      return VALID;
    }
    if (minor != null && minor.contains("invalid"))
    {
      return INVALID;
    }
    return INDETERMINED;
  }
}
