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
package de.bund.bsi.tr_esor.checktool;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.assertj.core.api.Assertions;
import org.junit.Test;

import de.bund.bsi.tr_esor.xaip.CredentialType;
import de.bund.bsi.tr_esor.xaip.VersionManifestType;


/**
 * Unit test class for {@link Toolbox}.
 *
 * @author PRE
 */
public class TestToolbox extends FileOutputChecker
{

  /**
   * Check if version manifest id is determined correctly.
   */
  @Test
  public void testGetIdFromManifestType()
  {
    VersionManifestType manifest = new VersionManifestType();
    manifest.setVersionID("v001");
    assertThat("manifest id", Toolbox.getId(manifest), is("v001"));
  }

  /**
   * Check if credential id is determined correctly.
   */
  @Test
  public void testGetIdFromCredentialType()
  {
    CredentialType cred = new CredentialType();
    cred.setCredentialID("cred1");
    assertThat("cred id", Toolbox.getId(cred), is("cred1"));
  }

  /**
   * Check if unsupported type causes exception.
   */
  @Test
  public void testGetIdWithUnsopportedType()
  {
    Assertions.assertThatException()
              .isThrownBy(() -> Toolbox.getId("dummy"))
              .withMessageContaining("Unsupported type java.lang.String");
  }

  /**
   * Check if null is handled.
   */
  @Test
  @SuppressWarnings("PMD.JUnitAssertionsShouldIncludeMessage")
  public void testSanitizeFileNameWithNull()
  {
    String sanitizedString = Toolbox.sanitizeFileName(null);
    assertThat(sanitizedString, is(nullValue()));
  }

  /**
   * Check if empty string is handled.
   */
  @Test
  @SuppressWarnings("PMD.JUnitAssertionsShouldIncludeMessage")
  public void testSanitizeWithEmptyString()
  {
    String sanitizedString = Toolbox.sanitizeFileName("");
    assertThat(sanitizedString, is(""));
  }

  /**
   * Check if a dot is handled.
   */
  @Test
  @SuppressWarnings("PMD.JUnitAssertionsShouldIncludeMessage")
  public void testSanitizeFileNameDot()
  {
    String sanitizedString = Toolbox.sanitizeFileName(".");
    assertThat(sanitizedString, is("."));
  }

  /**
   * Check if alphanumeric characters are not replaced.
   */
  @Test
  @SuppressWarnings("PMD.JUnitAssertionsShouldIncludeMessage")
  public void testSanitizeFileNameAlphaNumeric()
  {
    String sanitizedString = Toolbox.sanitizeFileName("QWERTZUIOPASDFGHJKLYXCVBNMqwertzuiopasdfghjklyxcvbnm1234567890");
    assertThat(sanitizedString, is("QWERTZUIOPASDFGHJKLYXCVBNMqwertzuiopasdfghjklyxcvbnm1234567890"));
  }

  /**
   * Check if german special chars are replaced.
   */
  @Test
  @SuppressWarnings("PMD.JUnitAssertionsShouldIncludeMessage")
  public void testSanitizeFileNameGermanSpecialChars()
  {
    String sanitizedString = Toolbox.sanitizeFileName("ÄÖÜäöüß");
    assertThat(sanitizedString, is("_______"));
  }

  /**
   * Check if forbidden filesystem characters are replaced.
   */
  @Test
  @SuppressWarnings("PMD.JUnitAssertionsShouldIncludeMessage")
  public void testSanitizeFileNameForbiddenFilesystemChars()
  {
    char[] forbiddenChars = {'*', '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', ' ', '\0', '\n', '_'};
    String sanitizedString = Toolbox.sanitizeFileName(new String(forbiddenChars));
    assertThat(sanitizedString, is("_______________"));
  }

}
