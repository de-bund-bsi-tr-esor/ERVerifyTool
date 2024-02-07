package de.bund.bsi.tr_esor.checktool.data;

import java.io.IOException;

import de.bund.bsi.tr_esor.checktool.Toolbox;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;
import de.bund.bsi.tr_esor.xaip.DataObjectType;


/**
 * Wrapper class for inline signed data objects.
 */
public class InlineSignedDataObject extends InlineSignedData
{

    private final DataObjectType data;

    /**
     * Create a wrapper object for an inline signature on a DataObject
     */
    public InlineSignedDataObject(Reference ref, LXaipReader lXaipReader, DataObjectType data)
    {
        super(ref, lXaipReader);
        this.data = data;
    }

    @Override
    public byte[] readBinaryData() throws IOException
    {
        return Toolbox.readBinaryData(lXaipReader, data);
    }
}
