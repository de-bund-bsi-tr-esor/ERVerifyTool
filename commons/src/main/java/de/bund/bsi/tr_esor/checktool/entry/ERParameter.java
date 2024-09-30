package de.bund.bsi.tr_esor.checktool.entry;

import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;

/**
 * Stores evidence records and associated values with it. This Class allows the validation of multiple Evidence Records at once.
 */
public class ERParameter
{

    /** evidence record given separately as input */
    private EvidenceRecord er;

    /** where that element came from */
    private Reference erRef;

    /** version of XAIP addressed by evidence record given separately within an XML structure. */
    private String xaipVersionAddressdByEr;

    /** AOID of XAIP addressed by evidence record given separately within an XML structure. */
    private String xaipAoidAddressdByEr;

    /**
     * Sets the detached evidence record to verify.
     */
    public void setEr(EvidenceRecord evidenceRecord)
    {
        this.er = evidenceRecord;
    }

    /**
     * Sets a XAIP version specified in XML with separately given ER.
     */
    public void setXaipVersionAddressedByEr(String xaipVersionAddressdByEr)
    {
        this.xaipVersionAddressdByEr = xaipVersionAddressdByEr;
    }

    /**
     * Sets a reference where the detaches ER came from.
     */
    public void setErRef(Reference erReference)
    {
        this.erRef = erReference;
    }

    /**
     * Sets a XAIP AOID specified in XML with separately given ER.
     */
    public void setXaipAoidAddressedByEr(String aoid)
    {
        this.xaipAoidAddressdByEr = aoid;
    }

    /**
     * Returns the detached evidence record to verify.
     */
    public EvidenceRecord getEr()
    {
        return er;
    }

    /**
     * Returns a XAIP version specified in XML with separately given ER.
     */
    public String getXaipVersionAddressedByEr()
    {
        return xaipVersionAddressdByEr;
    }

    /**
     * Returns reference where the detaches ER came from.
     */
    public Reference getErRef()
    {
        return erRef;
    }

    /**
     * Returns a XAIP AOID specified in XML with separately given ER.
     */
    public String getXaipAoidAddressedByEr()
    {
        return xaipAoidAddressdByEr;
    }
}
