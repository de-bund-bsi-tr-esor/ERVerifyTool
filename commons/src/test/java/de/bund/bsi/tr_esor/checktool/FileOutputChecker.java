/*-
 * Copyright (c) 2018
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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.io.FileMatchers.anExistingDirectory;
import static org.hamcrest.io.FileMatchers.anExistingFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;

import org.junit.After;
import org.junit.Before;


/**
 * Base class for tests using output into the file system.
 *
 * @author TT
 */
public class FileOutputChecker
{

  /**
   * Output folder, will be provided
   */
  protected Path destination;

  /**
   * Creates output directory.
   */
  @Before
  public void setUp() throws Exception
  {
    destination = Paths.get(System.getProperty("java.io.tmpdir"), getClass().getSimpleName());
    cleanUp();
    assertThat("create destination dir '" + destination + "'", destination.toFile().mkdirs(), equalTo(true));
  }

  @After
  public void tearDown() throws Exception
  {
    cleanUp();
  }

  /**
   * Asserts that a file exists.
   */
  protected void assertFileExists(String relativeFilePath)
  {
    assertThat(file(relativeFilePath).toFile(), anExistingFile());
  }

  /**
   * Asserts that a file not exists.
   */
  protected void assertFileNotExists(String relativeFilePath)
  {
    assertThat(file(relativeFilePath).toFile(), not(anExistingFile()));
  }

  /**
   * Asserts that a folder exists.
   */
  protected void assertFolderExists(String relativeFolderPath)
  {
    assertThat(file(relativeFolderPath).toFile(), anExistingDirectory());
  }

  /**
   * Asserts that the content of a specified file contains given substring.
   */
  protected void assertFileContains(String relativeFilePath, String expectedSubstring) throws Exception
  {
    assertThat(content(relativeFilePath), containsString(expectedSubstring));
  }

  /**
   * Asserts that the content of a specified file matches given pattern.
   */
  protected void assertFileContainsPattern(String relativeFilePath, String expectedPattern) throws Exception
  {
    assertThat(content(relativeFilePath), matchesPattern(expectedPattern));
  }

  /**
   * Asserts that the content of a specified file does not contain the given substring.
   */
  protected void assertFileNotContains(String relativeFilePath, String unexpectedSubstring) throws Exception
  {
    assertThat(content(relativeFilePath), not(containsString(unexpectedSubstring)));
  }

  /**
   * Asserts that the content of a specified file does not contain the given pattern.
   */
  protected void assertFileNotContainsPattern(String relativeFilePath, String unexpectedPattern)
    throws Exception
  {
    assertThat(content(relativeFilePath), not(matchesPattern(unexpectedPattern)));
  }

  /**
   * content of file as String
   */
  protected String content(String relativeFilePath) throws Exception
  {
    assertFileExists(relativeFilePath);
    return Files.readAllLines(file(relativeFilePath)).toString();
  }

  private Path file(String relativeFilePath)
  {
    return destination.resolve(relativeFilePath);
  }

  private void cleanUp() throws IOException
  {
    if (destination.toFile().exists())
    {
      Files.walk(destination).sorted(Comparator.reverseOrder()).map(Path::toFile).forEach(File::delete);
    }
  }
}
