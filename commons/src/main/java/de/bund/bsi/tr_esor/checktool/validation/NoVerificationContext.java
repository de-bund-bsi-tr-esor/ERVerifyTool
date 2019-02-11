package de.bund.bsi.tr_esor.checktool.validation;

import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Context for situations where no verification is possible.
 *
 * @author ETR
 */
public class NoVerificationContext extends ValidationContext<Object>
{

  private final String reason;

  /**
   * Constructs a context that describes that no verification was possible because of the given reason.
   *
   * @param profileName
   * @param reason given reason for the verification being impossible
   */
  public NoVerificationContext(String profileName, String reason)
  {
    super(new Reference(null), null, profileName, null);
    this.reason = reason;
  }

  /**
   * Constructs a context that describes that no verification was possible because of the given reason. This
   * version takes a reference that will be used for the signed object identifier in the report generated.
   *
   * @param profileName
   * @param reason given reason for the verification being impossible
   */
  public NoVerificationContext(Reference reference, String profileName, String reason)
  {
    super(reference, null, profileName, null);
    this.reason = reason;
  }

  /**
   * There is no class to be validated as there is no validation possible when this context is used.
   */
  @Override
  public Class<Object> getTargetClass()
  {
    return Object.class;
  }

  /**
   * Gives a String containing the reason why the verification is impossible
   *
   * @return reason for verification being impossible
   */
  public String getReason()
  {
    return reason;
  }

}
