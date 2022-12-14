package de.bund.bsi.tr_esor.checktool.data;

/**
 * Class that represents any kind of unsupported input data
 */
public final class UnsupportedData
{

  private final String message;

  /** create marker for unsupported data with message */
  public UnsupportedData(String message)
  {
    this.message = message;
  }

  /** get the message */
  public String getMessage()
  {
    return message;
  }
}
