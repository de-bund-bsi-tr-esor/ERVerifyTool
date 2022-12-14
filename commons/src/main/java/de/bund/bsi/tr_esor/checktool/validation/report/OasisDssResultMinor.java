package de.bund.bsi.tr_esor.checktool.validation.report;

/**
 * Possible minor result values for element {@code<Result>} from
 * {@code urn:oasis:names:tc:dss:1.0:core:schema }.
 * <p>
 * Source: http://docs.oasis-open.org/dss/v1.0/oasis-dss-core-spec-v1.0-os.html<br>
 * Chapter: 2.6
 * </p>
 *
 * @author PRE
 */
public enum OasisDssResultMinor
{

  // One of the following <ResultMinor> values MUST be returned when the <ResultMajor> code is
  // Success.

  /**
   * The signature or timestamp is valid. Furthermore, the signature or timestamp covers all of the input
   * documents just as they were passed in by the client.
   */
  SUCCESS_VALID_FOR_ALL_DOCUMENTS(OasisDssResultMajor.SUCCESS,
                                  "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:OnAllDocuments"),

  /**
   * The signature or timestamp is valid. However, the signature or timestamp does not cover all of the input
   * documents that were passed in by the client.
   */
  SUCCESS_VALID_WITH_UNREFERENCED_DOCUMENTS(OasisDssResultMajor.SUCCESS,
                                            "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:NotAllDocumentsReferenced"),

  /**
   * The signature fails to verify, for example due to the signed document being modified or the incorrect key
   * being used.
   */
  SUCCESS_INVALID_SIGNATURE(OasisDssResultMajor.SUCCESS,
                            "urn:oasis:names:tc:dss:1.0:resultminor:invalid:IncorrectSignature"),

  /**
   * The signature is valid with respect to XML Signature core validation. In addition, the message also
   * contains VerifyManifestResults.<br>
   * Note: In the case that the core signature validation failed no attempt is made to verify the manifest.
   */
  SUCCESS_VALID_HAS_MANIFEST_RESULT(OasisDssResultMajor.SUCCESS,
                                    "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:HasManifestResults"),

  /**
   * The signature is valid however the timestamp on that signature is invalid.
   */
  SUCCESS_VALID_SIGNATURE_INVALID_TIMESTAMP(OasisDssResultMajor.SUCCESS,
                                            "urn:oasis:names:tc:dss:1.0:resultminor:valid:signature:InvalidSignatureTimestamp"),

  // The following <ResultMinor> values is suggest MAY be returned when the <ResultMajor> code is
  // RequesterError.

  /**
   * A ds:Reference element is present in the ds:Signature containing a full URI, but the corresponding input
   * document is not present in the request.
   */
  ERROR_REQUEST_REFERENCED_DOCUMENT_NOT_PRESENT(OasisDssResultMajor.REQUESTER_ERROR,
                                                "urn:oasis:names:tc:dss:1.0:resultminor:ReferencedDocumentNotPresent"),

  /**
   * The required key information was not supplied by the client, but the server expected it to do so.
   */
  ERROR_REQUEST_KEY_INFO_NOT_PROVIDED(OasisDssResultMajor.REQUESTER_ERROR,
                                      "urn:oasis:names:tc:dss:1.0:resultminor:KeyInfoNotProvided"),

  /**
   * The server was not able to create a signature because more than one RefUri was omitted.
   */
  ERROR_REQUEST_MORE_THAN_ONE_REF_URI(OasisDssResultMajor.REQUESTER_ERROR,
                                      "urn:oasis:names:tc:dss:1.0:resultminor:MoreThanOneRefUriOmitted"),

  /**
   * The value of the RefURI attribute included in an input document is not valid.
   */
  ERROR_REQUEST_INVALID_REF_URI(OasisDssResultMajor.REQUESTER_ERROR,
                                "urn:oasis:names:tc:dss:1.0:resultminor:InvalidRefURI"),

  /**
   * The server was not able to parse a Document.
   */
  ERROR_REQUEST_XML_NOT_PARSEABLE(OasisDssResultMajor.REQUESTER_ERROR,
                                  "urn:oasis:names:tc:dss:1.0:resultminor:NotParseableXMLDocument"),

  /**
   * The server doesn’t recognize or can’t handle any optional input.
   */
  ERROR_REQUEST_NOT_SUPPORTED(OasisDssResultMajor.REQUESTER_ERROR,
                              "urn:oasis:names:tc:dss:1.0:resultminor:NotSupported"),

  /**
   * The signature or its contents are not appropriate in the current context. For example, the signature may
   * be associated with a signature policy and semantics which the DSS server considers unsatisfactory.
   */
  ERROR_REQUEST_INAPPROPRIATE_SIGNATURE(OasisDssResultMajor.REQUESTER_ERROR,
                                        "urn:oasis:names:tc:dss:1.0:resultminor:Inappropriate:signature"),

  // Further values for <ResultMinor> associated with <ResultMajor> code
  // urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError are left open to the implementer
  // or profile to be defined with in their namespaces.

  // The following <ResultMinor> values MAY be returned when the <ResultMajor> code is ResponderError.

  /**
   * The processing of the request failed due to an error not covered by the existing error codes. Further
   * details should be given in the result message for the user which may be passed on to the relevant
   * administrator.
   */
  ERROR_RESPONSE_GENERAL_ERROR(OasisDssResultMajor.RESPONDER_ERROR,
                               "urn:oasis:names:tc:dss:1.0:resultminor:GeneralError"),

  /**
   * Locating the identified key failed (e.g. look up failed in directory or in local key file).
   */
  ERROR_RESPONSE_KEY_LOOKUP_FAILED(OasisDssResultMajor.RESPONDER_ERROR,
                                   "urn:oasis:names:tc:dss:1.0:resultminor:invalid:KeyLookupFailed"),

  // Further values for <ResultMinor> associated with <ResultMajor> code
  // urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError are left open to the implementer
  // or profile to be defined within their namespaces.

  // The following <ResultMinor> values MAY be returned when the <ResultMajor> code is
  // InsufficientInformation.

  /**
   * The relevant certificate revocation list was not available for checking.
   */
  INSUFFICIENT_CRL_NOT_AVAILABLE(OasisDssResultMajor.INSUFFICIENT_INFORMATION,
                                 "urn:oasis:names:tc:dss:1.0:resultminor:CrlNotAvailiable"),

  /**
   * The relevant revocation information was not available via the online certificate status protocol.
   */
  INSUFFICIENT_OCSP_NOT_AVAILABLE(OasisDssResultMajor.INSUFFICIENT_INFORMATION,
                                  "urn:oasis:names:tc:dss:1.0:resultminor:OcspNotAvailiable"),

  /**
   * The chain of trust could not be established binding the public key used for validation to a trusted root
   * certification authority via potential intermediate certification authorities.
   */
  INSUFFICIENT_CERT_CHAIN_NOT_COMPLETE(OasisDssResultMajor.INSUFFICIENT_INFORMATION,
                                       "urn:oasis:names:tc:dss:1.0:resultminor:CertificateChainNotComplete");

  private final OasisDssResultMajor major;

  private final String uri;

  OasisDssResultMinor(OasisDssResultMajor major, String uri)
  {
    this.major = major;
    this.uri = uri;
  }

  /**
   * Get the appropriate major code for the minor represented
   */
  public OasisDssResultMajor getMajor()
  {
    return major;
  }

  /**
   * Get the URI representation as specified by OASIS
   *
   * @return String containing the URI including OASIS prefix
   */
  public String getUri()
  {
    return uri;
  }

  @Override
  public String toString()
  {
    return uri;
  }
}
