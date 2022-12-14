/*- Copyright (c) 2019
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
package de.bund.bsi.tr_esor.checktool.out;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.io.FileMatchers.anExistingDirectory;

import java.io.IOException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;


/**
 * Unit test class for {@link OutputFolder}.
 *
 * @author PRE
 */
public class TestOutputFolder extends FileOutputChecker
{

  /**
   * How JUnit checks exception cases.
   */
  @Rule
  public ExpectedException expected = ExpectedException.none();

  /**
   * Check if aoid folder is created correctly.
   */
  @Test
  public void testCreateAoidFolder() throws Exception
  {
    new OutputFolder(destination).createAoidFolder("no_aoid");

    assertFolderExists("no_aoid");
  }

  /**
   * Check if multiple aoid folders are created correctly.
   */
  @Test
  public void testCreateMultipleAoidFolders() throws Exception
  {
    new OutputFolder(destination).createAoidFolder("aoid(1)");

    assertFolderExists("aoid_1_");

    new OutputFolder(destination).createAoidFolder("aoid(2)");

    assertFolderExists("aoid_1_");
    assertFolderExists("aoid_2_");

    new OutputFolder(destination).createAoidFolder("aoid(1)");

    assertFolderExists("aoid_1_");
    assertFolderExists("aoid_1_(1)");
    assertFolderExists("aoid_2_");
  }

  /**
   * Check if folder with nasty chars is created correctly.
   */
  @Test
  public void testCreateAoidFolderWithNastyChars() throws Exception
  {
    new OutputFolder(destination).createAoidFolder("../..");

    assertFolderExists("_____");
  }

  /**
   * Check if sub folder is created correctly.
   */
  @Test
  public void testCreateAoidSubFolderSuccess() throws Exception
  {
    new OutputFolder(destination).createAoidFolder(".aoid with whitespaces")
                                 .createAoidSubFolder("awesome sub.folder");

    assertFolderExists("_aoid_with_whitespaces/awesome_sub_folder");
  }

  /**
   * Check if missing aoid folder creation is identified with specific exception.
   */
  @Test
  public void testCreateAoidSubFolderWithoutAoidFolder() throws IOException
  {
    expected.expectMessage("aoid folder must be created before");
    new OutputFolder(destination).createAoidSubFolder("awesome sub.folder");
  }

  /**
   * Check if a dot is handled.
   */
  @Test
  @SuppressWarnings("PMD.JUnitAssertionsShouldIncludeMessage")
  public void testSanitizeDirNameDot()
  {
    var sanitizedString = OutputFolder.sanitizeFolderName(".");
    assertThat(sanitizedString, is("_"));
  }

  /**
   * Check if alphanumeric characters are not replaced.
   */
  @Test
  @SuppressWarnings("PMD.JUnitAssertionsShouldIncludeMessage")
  public void testSanitizeDirNameAlphaNumeric()
  {
    var sanitizedString = OutputFolder.sanitizeFolderName("QWERTZUIOPASDFGHJKLYXCVBNMqwertzuiopasdfghjklyxcvbnm1234567890");
    assertThat(sanitizedString, is("QWERTZUIOPASDFGHJKLYXCVBNMqwertzuiopasdfghjklyxcvbnm1234567890"));
  }

  /**
   * Check if forbidden filesystem characters are replaced.
   */
  @Test
  @SuppressWarnings("PMD.JUnitAssertionsShouldIncludeMessage")
  public void testSanitizeDirNameForbiddenFilesystemChars()
  {
    var forbiddenChars = new char[]{'*', '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', ' ', '\0', '\n',
                                    '.', '_'};
    var sanitizedString = OutputFolder.sanitizeFolderName(new String(forbiddenChars));
    assertThat(sanitizedString, is("________________"));
  }

  /**
   * Check if multiple calls results in new directories with attached counter.
   */
  @Test
  public void testCreateNewFolderMultiply() throws IOException
  {
    var directoryName = "TestDirectory";

    var dirZero = destination.resolve(directoryName).toFile();
    var dirOne = destination.resolve(directoryName + "(1)").toFile();
    var dirTwo = destination.resolve(directoryName + "(2)").toFile();

    OutputFolder.createNewFolder(destination, directoryName);

    assertThat(dirZero.getAbsolutePath(), dirZero, anExistingDirectory());

    OutputFolder.createNewFolder(destination, directoryName);

    assertThat(dirZero.getAbsolutePath(), dirZero, anExistingDirectory());
    assertThat(dirOne.getAbsolutePath(), dirOne, anExistingDirectory());

    OutputFolder.createNewFolder(destination, directoryName);

    assertThat(dirZero.getAbsolutePath(), dirZero, anExistingDirectory());
    assertThat(dirOne.getAbsolutePath(), dirOne, anExistingDirectory());
    assertThat(dirTwo.getAbsolutePath(), dirTwo, anExistingDirectory());
  }
}
