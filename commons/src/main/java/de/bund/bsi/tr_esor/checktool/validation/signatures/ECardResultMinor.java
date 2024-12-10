package de.bund.bsi.tr_esor.checktool.validation.signatures;

/**
 * Enumeration containing the ResultMinor codes allowed for the verify method of the ECard-API.
 * <p>
 * The allowed ResultMinor values are defined in BSI TR-03112-2. The enumeration contains additional ResultMinor values defined in BSI
 * TR-03112-1 that are not mentioned in the description in BSI-TR03112-2 for the verify method but they fit better into our scheme of error
 * that may appear. This class is identical to the one used in the crypto service library.
 *
 * @author CKR
 * @author HMH
 * @author ETR
 */
public final class ECardResultMinor
{

    /**
     * Use of the function by the client application is not permitted.
     */
    public static final String NO_PERMISSION = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#noPermission";

    /**
     * Internal error.
     */
    public static final String INTERNAL_ERROR = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError";

    /**
     * There was some problem with a provided or omitted parameter.
     */
    public static final String PARAMETER_ERROR = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError";

    /**
     * Communication error.
     */
    public static final String COMMUNICATION_ERROR = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/dp#communicationError";

    /**
     * The stated certificate is not available for the function. This could be due to an incorrect reference or a deleted data field.
     */
    public static final String CERTIFICATE_NOT_FOUND = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateNotFound";

    /**
     * The format of the stated certificate is unknown and cannot be interpreted.
     */
    public static final String CERTIFICATE_FORMAT_NOT_CORRECT =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateFormatNotCorrect";

    /**
     * Invalid certificate reference.
     */
    public static final String INVALID_CERTIFICATE_REFERENCE =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidCertificateReference";

    /**
     * The stated certificate chain is interrupted. It is therefore not possible to complete full verification up to the root certificate.
     */
    public static final String CERTIFICATE_CHAIN_INTERRUPTED =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateChainInterrupted";

    /**
     * It was not possible to resolve the object reference.
     */
    public static final String RESOLUTION_OF_OBJECT_REFERENCE_IMPOSSIBLE =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#resolutionOfObjectReferenceImpossible";

    /**
     * The transformation algorithm is not supported.
     */
    public static final String TRANSFORMATION_ALGORITHM_NOT_SUPPORTED =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#transformationAlgorithmNotSupported";

    /**
     * The viewer is unknown or not available.
     */
    public static final String UNKNOWN_VIEWER = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#unknownViewer";

    /**
     * The certificate path was not checked. Due to some problems it was not possible to validate the certificate path.
     */
    public static final String CERTIFICATE_PATH_NOT_VALIDATED =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificatePathNotValidated";

    /**
     * The certificate status was not checked. Due to some problems it was not possible to check the certificate status.
     */
    public static final String CERTIFICATE_STATUS_NOT_CHECKED =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateStatusNotChecked";

    /**
     * The signature manifest was not verified. This is a warning.
     */
    public static final String SIGNATURE_MANIFEST_NOT_CHECKED =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureManifestNotCheckedWarning";

    /**
     * The suitability of the signature and hash algorithms was not checked.
     */
    public static final String SUITABILITY_OF_ALGORITHMS_NOT_CHECKED =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#suitabilityOfAlgorithmsNotChecked";

    /**
     * No signature-related data were found (detached signature without EContent).
     */
    public static final String DETACHED_SIGNATURE_WITHOUT_E_CONTENT =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#detachedSignatureWithoutEContent";

    /**
     * It is not possible to interpret revocation information.
     */
    public static final String IMPROPER_REVOCATION_INFORMATION =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#improperRevocationInformation";

    /**
     * Verification of a signature manifest has failed.
     */
    public static final String SIGNATURE_MANIFEST_NOT_CORRECT =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#SignatureManifestNotCorrect";

    /**
     * Stated hash algorithm is not supported.
     */
    public static final String HASH_ALGORITHM_NOT_SUPPORTED =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/algorithm#hashAlgorithmNotSupported";

    /**
     * The stated signature algorithm is not supported.
     */
    public static final String SIGNATURE_ALGORITHM_NOT_SUPPORTED =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/algorithm#signatureAlgorithmNotSupported";

    /**
     * The security of the signature algorithm is not suitable at the relevant point of time.
     */
    public static final String SIGNATURE_ALGORITHM_NOT_SUITABLE =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureAlgorithmNotSuitable";

    /**
     * The security of the hash algorithm is not suitable at the relevant point of time.
     */
    public static final String HASH_ALGORITHM_NOT_SUITABLE =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#hashAlgorithmNotSuitable";

    /**
     * The calculated digest of the message is not equal to the message digest in the MessageDigest-attribute of the CMS-Signature or the
     * DigestValue-element of the XML-signature respectively.
     */
    public static final String WRONG_MESSAGE_DIGEST = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#wrongMessageDigest";

    /**
     * The verified signature is not valid.
     */
    public static final String INVALID_SIGNATURE = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/sal#invalidSignature";

    // The following minors are defined in BSI-TR03112-1 section 4.2.3.6 Signature but not in the verify method.
    // The minors fit better the minors that are received from the CSL and are better explaining the problem

    /**
     * The format of the transmitted signature does not correspond to the respective specification. This error occurs when a supported
     * format is recognized (e.g. in accordance with [RFC3275] or [RFC3369]; but the signature does not meet the respective form
     * requirements. If the transmitted format was already not recognized, error / .../il/signature#signatureFormatNotSupported is
     * returned.
     */
    public static final String INVALID_SIGNATURE_FORMAT =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidSignatureFormat";

    /**
     * The certificate has been revoked.
     */
    public static final String CERTIFICATE_REVOKED = "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#certificateRevoked";

    /**
     * The reference time is outside the validity period of a certificate.
     */
    public static final String REFERENCED_TIME_NOT_WITHIN_CERTIFICATE_VALIDITY_PERIOD =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#referenceTimeNotWithinCertificateValidityPeriod"; // NOPMD
    // long
    // name
    // intentional

    /**
     * The certificate path is invalid.
     */
    public static final String INVALID_CERTIFICATE_PATH =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#invalidCertificatePath";

    /**
     * The signature format is not supported or no signature could be found
     */
    public static final String SIGNATURE_FORMAT_NOT_SUPPORTED =
        "http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureFormatNotSupported";

}
