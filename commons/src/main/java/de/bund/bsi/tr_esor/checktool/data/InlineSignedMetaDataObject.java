package de.bund.bsi.tr_esor.checktool.data;

import java.io.IOException;

import de.bund.bsi.tr_esor.checktool.Toolbox;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;
import de.bund.bsi.tr_esor.xaip.MetaDataObjectType;


/**
 * Wrapper class for inline signed metadata objects.
 */
public class InlineSignedMetaDataObject extends InlineSignedData
{

  private final MetaDataObjectType meta;

  /**
   * Create a wrapper object for an inline signature on a MetaDataObject
   */
  public InlineSignedMetaDataObject(Reference ref, LXaipReader lXaipReader, MetaDataObjectType meta)
  {
    super(ref, lXaipReader);
    this.meta = meta;
  }

  @Override
  public byte[] readBinaryData() throws IOException
  {
    return Toolbox.readBinaryData(lXaipReader, meta);
  }
}
