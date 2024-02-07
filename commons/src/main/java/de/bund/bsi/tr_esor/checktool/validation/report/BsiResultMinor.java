package de.bund.bsi.tr_esor.checktool.validation.report;

/**
 * Possible minor result values for Reports defined by Bsi TR-ESOR
 */
public enum BsiResultMinor
{

    PARAMETER_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#parameterError"),
    NOT_SUPPORTED("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/arl/notSupported"),
    INVALID_FORMAT(" http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/invalidFormat"),
    HASH_VALUE_MISMATCH("http://www.bsi.bund.de/tr-esor/api/1.3/resultminor/hashValueMismatch"),
    INTERNAL_ERROR("http://www.bsi.bund.de/ecard/api/1.1/resultminor/al/common#internalError"),
    SIGNATURE_FORMAT_NOT_SUPPORTED("http://www.bsi.bund.de/ecard/api/1.1/resultminor/il/signature#signatureFormatNotSupported");

    private final String uri;

    BsiResultMinor(String uri)
    {
        this.uri = uri;
    }

    /**
     * Get the URI representation as specified by OASIS
     *
     * @return String containing the URI including BSI prefix
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
