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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.bouncycastle.tsp.TimeStampToken;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.BasisErsECardTimeStampValidator;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;
import de.bund.bsi.tr_esor.checktool.validation.report.TimeStampReport;


/**
 * Test for detection of generic type arguments in a class.
 *
 * @author TT
 */
public class TestTypeAnalyzer
{

  /**
   * Asserts that the type analyzer finds out the correct generic types of a validator even in a non-trivial
   * class hierarchy.
   */
  @Test
  public void checkValidator()
  {
    var systemUnderTest = new TypeAnalyzer(BasisErsECardTimeStampValidator.class);
    assertThat("target class",
               systemUnderTest.getFirstMatchingTypeArgument(TimeStampToken.class).getName(),
               is(TimeStampToken.class.getName()));
    assertThat("Context class",
               systemUnderTest.getFirstMatchingTypeArgument(ValidationContext.class).getName(),
               is(ErValidationContext.class.getName()));
    assertThat("Report class",
               systemUnderTest.getFirstMatchingTypeArgument(ReportPart.class).getName(),
               is(TimeStampReport.class.getName()));

  }
}
