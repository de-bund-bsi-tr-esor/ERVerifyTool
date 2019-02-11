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
package de.bund.bsi.tr_esor.checktool.xml;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.hamcrest.Matcher;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.xaip._1.CredentialType;
import de.bund.bsi.tr_esor.xaip._1.EvidenceRecordType;
import de.bund.bsi.tr_esor.xaip._1.XAIPType;


/**
 * Unit test for {@link XaipReader}.
 *
 * @author BVO
 */
public class TestXaipReader
{

  private static final Reference REFERENCE = new Reference("XAIP");

  /** Used to expect exception in tests. */
  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  private XaipReader systemUnderTest;

  /**
   * Creates new {@link XaipReader} for an example XAIP.
   *
   * @throws Exception
   */
  @Before
  public void initializeSystemUnderTest() throws Exception
  {
    TestUtils.loadDefaultConfig();
    XAIPType xaip = XmlHelper.parseXaip(TestXaipReader.class.getResourceAsStream("/xaip/xaip_ok_ers.xml"));
    systemUnderTest = new XaipReader(xaip, REFERENCE);
  }

  /**
   * Asserts that the EvidenceRecords can be obtained.
   */
  @Test
  public void testGetEvidenceRecords()
  {
    List<EvidenceRecordType> evidenceRecords = systemUnderTest.getEvidenceRecords()
                                                              .values()
                                                              .stream()
                                                              .map(CredentialType::getEvidenceRecord)
                                                              .collect(Collectors.toList());
    assertThat(evidenceRecords, hasSize(1));
    assertThat(evidenceRecords.get(0).getAOID(), is("adc7ae71-bd2b-496f-83ec-1e8b11ad3161"));
    assertThat(evidenceRecords.get(0).getVersionID(), is("V001"));
  }

  /**
   * Asserts exception with useful message in case of illegal version ID.
   *
   * @throws Exception
   */
  @Test
  public void testGetProtectedElementsByWrongVersionID() throws Exception
  {
    expectedException.expect(IllegalArgumentException.class);
    expectedException.expectMessage("unknown versionID");
    systemUnderTest.getProtectedElements("Nada");
  }

  /**
   * Asserts that protected elements can be obtained for a valid version ID.
   *
   * @throws Exception
   */
  @Test
  public void testGetProtectedElements() throws Exception
  {
    Map<Reference, byte[]> protectedElements = systemUnderTest.getProtectedElements("V001");
    checkElement(protectedElements, "dataObjectID:data2_V001", startsWith("Dies ist ein Testdokument"));
    checkElement(protectedElements, "metaDataID:data2_meta_V001", startsWith("<esor:metaDataObject"));
    checkElement(protectedElements,
                 "metaDataID:data2_meta_V001",
                 containsString("data for qualified signature"));
    checkElement(protectedElements, "versionID:V001", startsWith("<esor:versionManifest"));
  }

  private void checkElement(Map<Reference, byte[]> protectedElements, String field, Matcher<String> expected)
  {
    assertThat("Content of " + field,
               new String(protectedElements.get(REFERENCE.newChild(field)), StandardCharsets.UTF_8),
               expected);
  }
}
