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

import jakarta.xml.bind.JAXBException;

import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.Toolbox;
import de.bund.bsi.tr_esor.checktool.validation.signatures.DetachedSignatureValidationContext;
import de.bund.bsi.tr_esor.checktool.xml.ComprehensiveXaipSerializer;
import de.bund.bsi.tr_esor.checktool.xml.XaipSerializer;
import de.bund.bsi.tr_esor.xaip.DataObjectType;


/**
 * Export content of data object to file.
 *
 * @author PRE
 */
public class XaipObjectWriter
{

  private static final Logger LOG = LoggerFactory.getLogger(DataObjectType.class);

  private OutputFolder outFolder;

  private ComprehensiveXaipSerializer xaipSerializer;

  /**
   * @param outputFolder information about output folder
   * @return this (fluid api)
   */
  public XaipObjectWriter withOutputFolder(OutputFolder outputFolder)
  {
    this.outFolder = outputFolder;
    return this;
  }

  /**
   * @param serializer used to get data object content which is send to validation
   * @return this (fluid api)
   */
  public XaipObjectWriter withXaipSerializer(XaipSerializer serializer)
  {
    if (serializer instanceof ComprehensiveXaipSerializer)
    {
      this.xaipSerializer = (ComprehensiveXaipSerializer)serializer;
    }
    return this;
  }

  /**
   * Write given data object to<br>
   * {@literal <destDir>/<aoid>/<data object id>/<data object id>.<data object extension>}
   *
   * @param data data object which should be written down
   */
  public void write(DataObjectType data)
  {
    if (data == null)
    {
      LOG.error("nothing to write because data object is null");
      return;
    }

    try
    {
      var dataObjectId = data.getDataObjectID();

      var targetFolder = outFolder.createAoidSubFolder(dataObjectId);

      var extension = Toolbox.getPreferredExtension(data);
      var dataAsBytes = xaipSerializer.serialize(data);
      write(targetFolder, dataObjectId, extension, dataAsBytes);
    }
    catch (IOException | JAXBException | CanonicalizationException | InvalidCanonicalizerException e)
    {
      LOG.error("serializing data object failed", e);
    }
  }

  /**
   * Write given signature and data objects for detached signature to<br>
   * {@literal <destDir>/<aoid>/<credential object
   * id>/signature.dat}<br>
   * and<br>
   * {@literal <destDir>/<aoid>/<credential object id>/<data object id>.<data object extension>}
   *
   * @param ctx detached signature validation objects with data objects
   */
  @SuppressWarnings("PMD.DataflowAnomalyAnalysis")
  public void write(DetachedSignatureValidationContext ctx)
  {
    if (ctx == null)
    {
      LOG.error("nothing to write because context is null");
      return;
    }

    try
    {
      var credentialObjectId = ctx.getReference().toString();
      var targetFolder = outFolder.createAoidSubFolder(credentialObjectId);

      var signatureValue = ctx.getReference().getSignatureValue();
      if (signatureValue == null)
      {
        LOG.error("signature value is null");
      }
      else
      {
        write(targetFolder, "signature", ".dat", signatureValue);
      }

      for ( var entry : ctx.getProtectedDataByID().entrySet() )
      {
        var dataObjectId = entry.getKey().relativize(ctx.getReference());
        var extension = ctx.getPreferredExtension(entry.getKey());
        var dataAsBytes = entry.getValue();
        write(targetFolder, dataObjectId, extension, dataAsBytes);
      }
    }
    catch (IOException e)
    {
      LOG.error("serializing context failed", e);
    }
  }

  private void write(Path targetFolder, String fileName, String extension, byte[] data) throws IOException
  {
    var cleanFileNameWithExtension = Toolbox.sanitizeFileName(fileName + extension);
    var targetFile = targetFolder.resolve(cleanFileNameWithExtension);

    LOG.info("export data to '{}'", targetFile);

    Files.write(targetFile, data);
  }

}
