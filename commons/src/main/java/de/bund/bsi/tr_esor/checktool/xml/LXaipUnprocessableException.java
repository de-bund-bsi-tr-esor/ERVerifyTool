package de.bund.bsi.tr_esor.checktool.xml;


/**
 * @author SMU
 */
public class LXaipUnprocessableException extends RuntimeException
{

    private static final long serialVersionUID = 7431893228230502289L;

    private final String dataObjectId;

    /**
     *
     */
    public LXaipUnprocessableException(String message, String dataObjectId)
    {
        super(message);
        this.dataObjectId = dataObjectId;
    }

    /**
     *
     */
    public LXaipUnprocessableException(String message, String dataObjectId, Throwable cause)
    {
        super(message, cause);
        this.dataObjectId = dataObjectId;
    }

    /**
     * Get the affected data object ID
     */
    public String getDataObjectId()
    {
        return dataObjectId;
    }
}
