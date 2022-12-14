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
import static org.hamcrest.Matchers.nullValue;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;


/**
 * Unit test for selecting some value based on profile and best matching target class.
 *
 * @author HMA, TT
 */
public class TestValidatorRepository
{

  /**
   * Asserts that the system prefers values in the profile over general definitions and chooses the most
   * specific matching class.
   */
  @Test
  public void select()
  {
    var systemUnderTest = new ValidatorRepository();
    systemUnderTest.addGeneral(() -> "map", Map.class, ValidationContext.class, ReportPart.class);
    systemUnderTest.addGeneral(() -> "hashmap", HashMap.class, ValidationContext.class, ReportPart.class);
    systemUnderTest.addGeneral(() -> "treemap", TreeMap.class, ValidationContext.class, ReportPart.class);
    systemUnderTest.addToProfile(() -> "treemap2",
                                 TreeMap.class,
                                 ValidationContext.class,
                                 ReportPart.class,
                                 "2");
    systemUnderTest.addToProfile(() -> "map3", Map.class, ValidationContext.class, ReportPart.class, "3");

    assertThat("direct match in profile",
               systemUnderTest.get(TreeMap.class, ValidationContext.class, ReportPart.class, "2").get(),
               is("treemap2"));
    assertThat("indirect match in profile (over direct in general)",
               systemUnderTest.get(HashMap.class, ValidationContext.class, ReportPart.class, "3").get(),
               is("map3"));
    assertThat("not in profile",
               systemUnderTest.get(HashMap.class, ValidationContext.class, ReportPart.class, "2").get(),
               is("hashmap"));
    assertThat("unknown profile",
               systemUnderTest.get(TreeMap.class, ValidationContext.class, ReportPart.class, "unknown").get(),
               is("treemap"));
    assertThat("indirect match",
               systemUnderTest.get(SortedMap.class, ValidationContext.class, ReportPart.class, "2").get(),
               is("map"));
    assertThat("best match",
               systemUnderTest.get(LinkedHashMap.class, ValidationContext.class, ReportPart.class, "2").get(),
               is("hashmap"));
    assertThat("no match",
               systemUnderTest.get(String.class, ValidationContext.class, ReportPart.class, "2"),
               nullValue());
  }
}
