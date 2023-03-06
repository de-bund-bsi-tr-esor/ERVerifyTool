/*-
 * Copyright (c) 2017
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
package de.bund.bsi.tr_esor.checktool.validation.report;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationResultType;

import de.bund.bsi.tr_esor.checktool.validation.NoValidatorException;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.VerificationResultCreator;


/**
 * Base class for report parts which may be returned by validators.
 * <p>
 * Implementing classes must define a constructor with single parameter of type {@link Reference}.
 * Furthermore, if other report parts are contained, you might want to define methods of that form:
 *
 * <pre>
 *
 * public &lt;T extends ReportPart&gt; void addChild(T childReport)
 * {
 *   updateCodes(childReport);
 *   // add the child to the internal report structure.
 * }
 * </pre>
 *
 * @author TT
 */
public class ReportPart
{

  /**
   * Priority levels for changing minor codes when updating codes.
   */
  public enum MinorPriority
  {
    /** set new minor code unless the code set previously was important */
    NORMAL,
    /** set new minor code unless existing code is most important */
    IMPORTANT,
    /** always set new minor code */
    MOST_IMPORTANT
  }

  /**
   * Major status of validation.
   */
  // sorry for the wrong initial value, need it to use the "worse" method.
  protected ValidationResultMajor major = ValidationResultMajor.VALID;

  /**
   * Minor status is String to enable further validators which might want to create own values.
   */
  private String minor;

  /**
   * Specifies whether a call to {@link #updateCodes(ReportPart)} or
   * {@link #updateCodes(ValidationResultMajor, String, MinorPriority, String, Reference)} replaces the minor
   * code.
   */
  private MinorPriority minorPriority;

  /**
   * Result message (free text) describing the current level validation.
   */
  private String message;

  private final Map<Reference, List<String>> subMessages = new HashMap<>();

  /**
   * Reference to the object the validation of which is reported.
   */
  private final Reference reference;

  boolean detailsPresent = true;

  /**
   * Creates a new report part for the given reference.
   *
   * @param reference describes the object which validation is reported
   */
  protected ReportPart(Reference reference)
  {
    this.reference = reference;
  }

  /**
   * Returns instance which states that no verification was done because of the reason given in the message.
   */
  public static ReportPart forNoVerification(Reference ref, String message)
  {
    var result = new ReportPart(ref);
    result.detailsPresent = false;
    result.major = ValidationResultMajor.INVALID;
    result.minor = BsiResultMinor.PARAMETER_ERROR.getUri();
    result.message = message;
    return result;
  }

  /**
   * Returns instance which states that no verification was done because of broken LXAIP integrity.
   */
  public static ReportPart forLXaipDigestMismatch(Reference ref, Exception exception)
  {
    var result = new ReportPart(ref);
    result.detailsPresent = false;
    result.major = ValidationResultMajor.INVALID;
    result.minor = BsiResultMinor.HASH_VALUE_MISMATCH.getUri();
    result.message = exception.getMessage();
    return result;
  }

  /**
   * Returns instance which states that no validator is available for that object.
   */
  public static ReportPart forNoValidator(Reference ref, NoValidatorException e)
  {
    var result = new ReportPart(ref);
    result.setNoValidator(e);
    return result;
  }

  /**
   * Sets result in case validator not available.
   */
  public void setNoValidator(NoValidatorException e)
  {
    major = ValidationResultMajor.INDETERMINED;
    minor = BsiResultMinor.INTERNAL_ERROR.getUri();
    message = e == null ? "no validator available" : e.getMessage();
    detailsPresent = false;
  }

  /**
   * Returns an instance indicating that no validation has been done because of unknown profile. In that case,
   * the application does neither know how to parse data nor how to validate objects.
   */
  public static ReportPart forNoProfile(Reference ref, String profileName)
  {
    var result = new ReportPart(ref);
    result.detailsPresent = false;
    result.major = ValidationResultMajor.INDETERMINED;
    result.minor = BsiResultMinor.PARAMETER_ERROR.getUri();
    result.message = "unsupported profile: " + profileName;
    return result;
  }

  /**
   * Changes own result codes in case that sub-validations were not OK.
   */
  public void updateCodes(ReportPart subPart)
  {
    updateCodes(subPart.major, subPart.minor, subPart.minorPriority, subPart.message, subPart.reference);
    subMessages.putAll(subPart.subMessages);
  }

  /**
   * Changes result codes and message according to codes produced by some validation. The major code may be
   * changed only to worse values (for instance from indetermined to invalid but not back). The new minor code
   * replaces the existing value if the major code was changed or the new priority is not less important than
   * the last one. Messages are collected, the object is able to use only the message(s) for current level or
   * create a summarized message including all the findings of any sub-validations.
   *
   * @param newMajor major code to use if it is worse than the current code
   * @param newMinor minor code to use if major code changes or priority is important enough
   * @param pr specifies when to set the minor code
   * @param newMessage message to use/append to the existing message
   * @param subRef reference to object the given message refers to
   */
  public void updateCodes(ValidationResultMajor newMajor,
                          String newMinor,
                          MinorPriority pr,
                          String newMessage,
                          Reference subRef)
  {
    var oldMajor = major;
    major = major.worse(newMajor);

    if (major != oldMajor || newMajor == oldMajor && notLessImportant(pr))
    {
      minor = newMinor;
      minorPriority = pr;
    }
    if (newMessage != null && newMajor != ValidationResultMajor.VALID)
    {
      if (subRef.equals(reference))
      {
        message = Optional.ofNullable(message).map(m -> m + ", " + newMessage).orElse(newMessage);
      }
      else
      {
        addSubmessage(subRef, newMessage);
      }
    }
  }

  /** Add a message to the report. Messages can also be added for valid results */
  public void addMessageOnly(String newMessage, Reference subRef)
  {
    if (subRef.equals(reference))
    {
      message = Optional.ofNullable(message).map(m -> m + ", " + newMessage).orElse(newMessage);
    }
    else
    {
      addSubmessage(subRef, newMessage);
    }
  }

  private boolean notLessImportant(MinorPriority pr)
  {
    return pr != null && (minorPriority == null || pr.ordinal() >= minorPriority.ordinal());
  }

  /**
   * Returns the overall result of validating an object and its children.
   */
  public VerificationResultType getOverallResult()
  {
    return VerificationResultCreator.create(major, minor, message);
  }

  /**
   * Returns the overall result of validating an object and its children, including all the child messages.
   */
  public VerificationResultType getOverallResultVerbose()
  {
    return VerificationResultCreator.create(major, minor, getSummarizedMessage());
  }

  /**
   * Returns the reference to the object this report part covers.
   */
  public Reference getReference()
  {
    return reference;
  }

  /**
   * Returns <code>true</code> if details are present in the internal data structure (details may be missing
   * if no validation was done due to technical problems).
   */
  public boolean isDetailsPresent()
  {
    return detailsPresent;
  }

  /**
   * Sets result in case parsing of the object failed.
   *
   * @param type object type which failed to parse
   */
  public void setNoParsedObject(String type)
  {
    detailsPresent = false;
    major = ValidationResultMajor.INVALID;
    minor = "http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/invalidFormat";
    message = type + " cannot be parsed";
  }

  /**
   * Returns a String containing all messages of current and sub elements in a human-readable form.
   */
  public String getSummarizedMessage()
  {
    var result = new StringBuilder();
    if (message != null)
    {
      result.append(message);
    }
    if (!subMessages.isEmpty())
    {
      Map<String, String> msgs = new TreeMap<>();
      subMessages.forEach((r, m) -> m.stream().forEach(subMessage -> addMessage(r, subMessage, msgs)));
      msgs.forEach((r, m) -> appendMesssage(result, r, m));
    }
    var summary = result.toString();
    return summary.isBlank() ? null : summary;
  }

  /** Add a message without adjusting codes. Can also add messages for valid case. */
  private void addMessage(Reference r, String m, Map<String, String> msgs)
  {
    var rel = r.relativize(reference);
    msgs.put(rel, Optional.ofNullable(msgs.get(rel)).map(s -> s + ", " + m).orElse(m));
  }

  private void addSubmessage(Reference r, String m)
  {
    if (subMessages.containsKey(r))
    {
      subMessages.get(r).add(m);
    }
    else
    {
      List<String> messages = new ArrayList<>();
      messages.add(m);
      subMessages.put(r, messages);
    }
  }

  private void appendMesssage(StringBuilder result, String relativeRef, String msg)
  {
    if (result.length() > 0)
    {
      result.append("\n");
    }
    if (!relativeRef.isEmpty())
    {
      result.append(relativeRef).append(": ");
    }
    result.append(msg);
  }

  @Override
  public String toString()
  {
    return reference + " {major: " + major + ", minor: " + minor + ", summarizedMessage: "
           + getSummarizedMessage() + "}";
  }

}
