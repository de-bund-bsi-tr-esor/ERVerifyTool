package de.bund.bsi.tr_esor.checktool.xml;

/**
 * @author SMU
 */
public class LXaipDigestMismatchException extends LXaipUnprocessableException
{

    private static final long serialVersionUID = 5805805599202020497L;

    /**
     * @param message
     */
    public LXaipDigestMismatchException(String message, String dataObjectId)
    {
        super(message, dataObjectId);
    }
}
