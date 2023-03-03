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

import java.io.IOException;

import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;
import de.bund.bsi.tr_esor.xaip.CredentialType;
import de.bund.bsi.tr_esor.xaip.DataObjectType;
import de.bund.bsi.tr_esor.xaip.MetaDataObjectType;
import de.bund.bsi.tr_esor.xaip.VersionManifestType;


/**
 * Toolbox for common required static methods.
 *
 * @author PRE
 */
public final class Toolbox
{

  private Toolbox()
  {
    // no instance required
  }

  /**
   * Determine file extension for data object.
   *
   * @param data data object
   * @return extension with dot
   */
  public static String getPreferredExtension(DataObjectType data)
  {
    var binData = data.getBinaryData();
    if (binData == null)
    {
      if (LXaipReader.isValidLXaipElement(data, data.getDataObjectID()))
      {
        return ".bin";
      }
      return ".xml";
    }

    if ("application/pdf".equals(binData.getMimeType()))
    {
      return ".pdf";
    }

    return ".bin";
  }

  /**
   * Determine Id from xaip object.
   *
   * @param value xaip object
   * @return Id as string
   */
  // TODO Might be duplicate from XaipReader
  public static String getId(Object value)
  {
    if (value instanceof DataObjectType)
    {
      return ((DataObjectType)value).getDataObjectID();
    }
    if (value instanceof MetaDataObjectType)
    {
      return ((MetaDataObjectType)value).getMetaDataID();
    }
    if (value instanceof CredentialType)
    {
      return ((CredentialType)value).getCredentialID();
    }
    if (value instanceof VersionManifestType)
    {
      return ((VersionManifestType)value).getVersionID();
    }
    throw new IllegalArgumentException("Unsupported type " + value.getClass().getName());
  }

  /**
   * Removes all parts of the string which may cause problems with file system and replaces it with an
   * underscore for files.
   */
  public static String sanitizeFileName(String str)
  {
    if (str == null)
    {
      return null;
    }

    return str.replaceAll("[^a-zA-Z0-9\\.]", "_");
  }

  /**
   * Helper Method to extract the binary data of a DataObjectType from a LXaip or Xaip
   */
  public static byte[] readBinaryData(LXaipReader lXaipReader, DataObjectType data) throws IOException
  {
    byte[] binaryData = null;
    if (lXaipReader.isValidLXaipElement(data, data.getDataObjectID()))
    {
      binaryData = lXaipReader.readBinaryData(data, data.getDataObjectID());
    }
    else if (data.getBinaryData() != null)
    {
      binaryData = data.getBinaryData().getValue().getInputStream().readAllBytes();
      data.getBinaryData().getValue().getInputStream().reset();
    }
    return binaryData;
  }

  /**
   * Helper Method to extract the binary data of a MetaDataObjectType from a LXaip or Xaip
   */
  public static byte[] readBinaryData(LXaipReader lXaipReader, MetaDataObjectType meta) throws IOException
  {
    byte[] binaryData = null;
    if (lXaipReader.isValidLXaipElement(meta, meta.getMetaDataID()))
    {
      binaryData = lXaipReader.readBinaryData(meta, meta.getMetaDataID());
    }
    else if (meta.getBinaryMetaData() != null)
    {
      binaryData = meta.getBinaryMetaData().getValue().getInputStream().readAllBytes();
      meta.getBinaryMetaData().getValue().getInputStream().reset();
    }
    return binaryData;
  }
}
