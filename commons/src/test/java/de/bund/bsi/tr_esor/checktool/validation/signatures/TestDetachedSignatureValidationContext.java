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

import java.util.Collections;

import org.assertj.core.api.Assertions;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Unit test for class {@link TestDetachedSignatureValidationContext}.
 *
 * @author PRE
 */
public class TestDetachedSignatureValidationContext
{

  /**
   * Assert that adding file extensions for unknown objects in the context fails.
   */
  @Test
  public void extensionForWrongObject()
  {
    DetachedSignatureValidationContext contextUnderTest = new DetachedSignatureValidationContext(null, null,
                                                                                                 Collections.emptyMap(),
                                                                                                 "");
    Assertions.assertThatExceptionOfType(IllegalArgumentException.class)
              .isThrownBy(() -> contextUnderTest.setPreferredExtension(new Reference("falsch"), "*.docx"))
              .withMessage("Not a reference of protected data: falsch");
  }
}
