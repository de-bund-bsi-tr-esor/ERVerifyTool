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
package de.bund.bsi.tr_esor.checktool.conf;

import java.util.Arrays;
import java.util.List;


/**
 * Provides constants for predefined profile names.
 *
 * @author HMA
 */
public final class ProfileNames
{

  /**
   * Default profile: RFC4998.
   */
  public static final String RFC4998 = "https://tools.ietf.org/html/rfc4998";

  /**
   * Common base name of both TR-ESOR-ERS profiles (BASIS-ERS and BASIS-XERS) specified in the same document.
   */
  private static final String TR_03125_BASE_NAME = "http://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03125/BSI_TR_03125_Anlage_ERS_V1_2.html";

  /**
   * Profile: Basis-ERS-Profil.
   * <p>
   * This profile name uses an anchor which does not exist at the defined URL to distinguish Basis-ERS-Profil
   * from Basis-XERS-Profil.
   */
  public static final String BASIS_ERS = TR_03125_BASE_NAME + "#Basis-ERS-Profil";

  private ProfileNames()
  {
    // static only
  }

  /**
   * Returns a list of all predefined profile names.
   */
  public static List<String> getPredefinedProfileNames()
  {
    return Arrays.asList(RFC4998, BASIS_ERS);
  }

}
