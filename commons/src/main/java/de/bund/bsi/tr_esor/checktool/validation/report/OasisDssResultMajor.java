package de.bund.bsi.tr_esor.checktool.validation.report;

/**
 * Possible major result values for element {@code<Result>} from {@code urn:oasis:names:tc:dss:1.0:core:schema }.
 * <p>
 * Source: http://docs.oasis-open.org/dss/v1.0/oasis-dss-core-spec-v1.0-os.html<br> Chapter: 2.6
 * </p>
 *
 * @author PRE
 */
public enum OasisDssResultMajor
{

    /**
     * The protocol executed successfully.
     */
    SUCCESS("urn:oasis:names:tc:dss:1.0:resultmajor:Success"),

    /**
     * The request could not be satisfied due to an error on the part of the requester.
     */
    REQUESTER_ERROR("urn:oasis:names:tc:dss:1.0:resultmajor:RequesterError"),

    /**
     * The request could not be satisfied due to an error on the part of the responder.
     * <p>
     * In case of doubt of who is responsible a urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError is assumed.
     * </p>
     */
    RESPONDER_ERROR("urn:oasis:names:tc:dss:1.0:resultmajor:ResponderError"),

    /**
     * The request could not be satisfied due to insufficient information.
     */
    INSUFFICIENT_INFORMATION("urn:oasis:names:tc:dss:1.0:resultmajor:InsufficientInformation");

    private final String uri;

    OasisDssResultMajor(String uri)
    {
        this.uri = uri;
    }

    /**
     * Get the appropriate enum value. Null is returned if no value matches the URI.
     */
    public static OasisDssResultMajor fromURI(String uri)
    {
        for (OasisDssResultMajor major : OasisDssResultMajor.values())
        {
            if (major.uri.equalsIgnoreCase(uri))
            {
                return major;
            }
        }
        return null;
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
