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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage;
import de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage.UsageType;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.AlgorithmUsageValidator;


/**
 * Basis-ERS-Profil requires the digest algorithms to be one of: SHA-256, SHA-384, SHA-512.
 *
 * @author HMA, TT
 */
public class BasisErsAlgorithmUsageValidator extends AlgorithmUsageValidator
{

  private static final Collection<String> ALLOWED_DIGESTS = Collections.unmodifiableList(Arrays.asList(// BSI-TR-ESOR-ERS-5.2.1:
                                                                                                       "1.3.36.3.2.1", // RIPEMD-160
                                                                                                       "1.3.14.3.2.26", // SHA-1
                                                                                                       "2.16.840.1.101.3.4.2.4", // SHA-224
                                                                                                       // BSI-TR-ESOR-ERS-5.1.1:
                                                                                                       "2.16.840.1.101.3.4.2.1", // SHA-256
                                                                                                       "2.16.840.1.101.3.4.2.2", // SHA-384
                                                                                                       "2.16.840.1.101.3.4.2.3") // SHA-512
  );

  @Override
  protected ValidationResultMinor check(AlgorithmUsage algo)
  {
    var result = super.check(algo);
    if (result == ValidationResultMinor.NULL && algo.getUsage() == UsageType.DATA_HASHING
        && !ALLOWED_DIGESTS.contains(algo.getOid()))
    {
      return ValidationResultMinor.HASH_ALGORITHM_NOT_SUITABLE;
    }
    return result;
  }

}
