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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Creates and manages output folders.
 *
 * @author PRE
 */
public class OutputFolder
{

  private static final Logger LOG = LoggerFactory.getLogger(OutputFolder.class);

  private final Path destinationFolder;

  private Path aoidFolder;

  private Path noAoidFolder;

  /**
   * Default Constructor
   *
   * @param destinationFolder base folder for storing output data
   */
  public OutputFolder(Path destinationFolder) throws IOException
  {
    Files.createDirectories(destinationFolder);
    this.destinationFolder = destinationFolder;

    LOG.debug("destinationFolder: {}", destinationFolder.toAbsolutePath());
  }

  /**
   * Each call creates a new aoid folder in destination directory:<br>
   * <b>{@literal <destinationFolder>/<aoid>/}</b> or <b>{@literal <destinationFolder>/<aoid>(<counter>)/}</b>
   *
   * @param aoid name of aoid folder (will be sanitized)
   * @return this (fluid api)
   * @throws IOException
   */
  public OutputFolder createAoidFolder(String aoid) throws IOException
  {
    var cleanAoid = sanitizeFolderName(aoid);
    this.aoidFolder = createNewFolder(destinationFolder, cleanAoid);

    LOG.debug("aoidFolder: {}", aoidFolder.toAbsolutePath());

    return this;
  }

  /**
   * Create a sub folder in aoid folder with the given name: <br>
   * {@literal <aoidFolder>/<name>}
   *
   * @param name sub folder name (will be sanitized)
   * @return path sub folder path object
   * @throws IOException
   */
  public Path createAoidSubFolder(String name) throws IOException
  {
    if (aoidFolder == null)
    {
      throw new IOException("aoid folder must be created before");
    }

    var cleanFolderName = sanitizeFolderName(name);
    var objectIdFolder = aoidFolder.resolve(cleanFolderName);
    Files.createDirectories(objectIdFolder);

    LOG.debug("objectIdFolder: {}", objectIdFolder.toAbsolutePath());

    return objectIdFolder;
  }

  /**
   * Create new directory.<br>
   * Adds counter if directory already exists.
   *
   * @param parent parent folder path
   * @param name name of the new directory
   * @return path of the new directory
   */
  @SuppressWarnings("PMD.DataflowAnomalyAnalysis")
  static Path createNewFolder(Path parent, String name) throws IOException
  {
    var cleanName = sanitizeFolderName(name);
    var dest = parent.resolve(cleanName);
    var counter = 1;
    while (dest.toFile().exists())
    {
      dest = parent.resolve(cleanName + "(" + counter++ + ")");
    }
    return Files.createDirectory(dest);
  }

  /**
   * Removes all parts of the string which may cause problems with file system and replaces it with an
   * underscore.
   */
  static String sanitizeFolderName(String folderName)
  {
    if (folderName == null)
    {
      return null;
    }

    var cleanFolderName = folderName.replaceAll("[^a-zA-Z0-9]", "_");

    LOG.debug("sanitized from '{}' to '{}'", folderName, cleanFolderName);

    return cleanFolderName;
  }

  /**
   * Get path for the AOID folder
   */
  public Path getAoidFolder()
  {
    return aoidFolder;
  }

  /**
   * Get folder path for no aoid
   */
  public Path noAoidDestinationFolder() throws IOException
  {
    if (noAoidFolder == null)
    {
      noAoidFolder = createNewFolder(destinationFolder, "no_aoid");
    }
    return noAoidFolder;
  }
}
