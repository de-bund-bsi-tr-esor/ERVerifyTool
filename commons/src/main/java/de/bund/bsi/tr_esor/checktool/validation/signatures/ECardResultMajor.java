package de.bund.bsi.tr_esor.checktool.validation.signatures;

/**
 * Enumeration containing the ResultMajor codes allowed for the verify method of the ECard-API.
 * <p>
 * The allowed ResultMajor values are defined in BSI TR-03112-2.
 *
 * @author ETR
 */
final class ECardResultMajor
{

  /**
   * Successful operation
   */
  public static final String OK = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#ok";

  /**
   * Operation concluded with problems (e.g. missing content or OCSP unavailable)
   */
  public static final String WARNING = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#warning";

  /**
   * Operation failed or data was checked as invalid.
   */
  public static final String ERROR = "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error";

}
