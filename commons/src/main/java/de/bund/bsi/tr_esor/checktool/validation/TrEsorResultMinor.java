package de.bund.bsi.tr_esor.checktool.validation;

/**
 * Examples of ResultMinor codes specified in TR-ESOR documents. This list is not complete.
 */
public enum TrEsorResultMinor
{

  NOT_SUPPORTED("http://www.bsi.bund.de/ecard/tr-esor/1.3/resultminor/arl/notSupported");

  private String value;

  TrEsorResultMinor(String value)
  {
    this.value = value;
  }

  @Override
  public String toString()
  {
    return value;
  }
}
