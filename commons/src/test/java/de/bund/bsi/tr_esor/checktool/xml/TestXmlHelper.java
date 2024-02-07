package de.bund.bsi.tr_esor.checktool.xml;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import org.etsi.uri._02918.v1_2.DataObjectReferenceType;
import org.junit.Test;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;


/**
 * Test the XML Helper
 */
@SuppressWarnings({"PMD.CommentRequired"})
public class TestXmlHelper
{

    /**
     * read a LXAIP
     */
    @Test
    public void canDeserializeLXaip() throws JAXBException
    {
        var xaip = XmlHelper.parseXaip(getClass().getResourceAsStream("/lxaip/lxaip_ok.xml"));
        var dataObject = xaip.getDataObjectsSection();
        assertThat(((JAXBElement)dataObject.getDataObject().get(0).getXmlData().getAny().get(0)).getValue(),
            instanceOf(DataObjectReferenceType.class));
        var dataReference =
            (DataObjectReferenceType)((JAXBElement)dataObject.getDataObject().get(0).getXmlData().getAny().get(0)).getValue();
        assertThat(dataReference.getURI(), is(notNullValue()));
        assertThat(dataReference.getDigestMethod(), is(notNullValue()));
        assertThat(dataReference.getDigestValue(), is(notNullValue()));
    }
}
