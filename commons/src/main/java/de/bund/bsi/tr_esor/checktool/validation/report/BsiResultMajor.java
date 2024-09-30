package de.bund.bsi.tr_esor.checktool.validation.report;

/**
 * Possible major result values for Reports defined by Bsi TR-ESOR
 */
public enum BsiResultMajor {

    OK("http://www.bsi.bund.de/tr-esor/api/1.3/resultmajor#ok"),
    WARNING("http://www.bsi.bund.de/tr-esor/api/1.3/resultmajor#warning"),
    ERROR("http://www.bsi.bund.de/tr-esor/api/1.3/resultmajor#error");

    private final String uri;

    BsiResultMajor(String uri)
    {
        this.uri = uri;
    }

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
