package de.bund.bsi.tr_esor.checktool.data;

import java.io.IOException;

import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;


/**
 * Wrapper class for inline signed data.
 */
public abstract class InlineSignedData
{

  private final Reference reference;

  protected final LXaipReader lXaipReader;

  protected InlineSignedData(Reference ref, LXaipReader lXaipReader)
  {
    this.reference = ref;
    this.lXaipReader = lXaipReader;
  }

  /** get reference for content */
  public Reference getReference()
  {
    return reference;
  }

  /** get binary content */
  public abstract byte[] readBinaryData() throws IOException;
}
