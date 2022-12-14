package de.bund.bsi.tr_esor.checktool.validation;

import java.util.List;


/**
 * Exception thrown in case a requested version is not present in the XAIP
 */
public class VersionNotFoundException extends IllegalArgumentException
{

  private static final long serialVersionUID = 9181839173640304634L;

  /**
   * Creates the exception for a version that could not be found.
   *
   * @param requestedVersion The version that was expected to be in the XAIP
   * @param availableVersions A list of available versions.
   */
  public VersionNotFoundException(String requestedVersion, List<String> availableVersions)
  {
    super(String.format("The requested version %s could not be found in the XAIP. Available versions are: %s",
                        requestedVersion,
                        availableVersions));
  }
}
