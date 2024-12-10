package de.bund.bsi.tr_esor.checktool.xml;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThrows;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.etsi.uri._02918.v1_2.DataObjectReferenceType;
import org.etsi.uri._02918.v1_2.ObjectFactory;
import org.junit.Before;
import org.junit.Test;
import org.w3._2000._09.xmldsig_.DigestMethodType;

import de.bund.bsi.tr_esor.xaip.BinaryDataType;
import de.bund.bsi.tr_esor.xaip.DataObjectType;

import jakarta.activation.DataHandler;
import oasis.names.tc.dss._1_0.core.schema.AnyType;


/**
 * Test class for the LXaipReader
 */
public class TestLXaipReader
{

    private LXaipReader sut;

    @Before
    public void setUp() throws Exception
    {
        sut = new LXaipReader(Path.of(getClass().getResource("/lxaip").toURI()));
    }

    @Test
    public void detectsXaip()
    {
        var dataObject = new DataObjectType();
        var binaryData = new BinaryDataType();
        var dataHandler = new DataHandler("some value".getBytes(StandardCharsets.US_ASCII), "text/plain");
        binaryData.setValue(dataHandler);
        dataObject.setBinaryData(binaryData);

        assertThat(sut.isValidLXaipElement(dataObject, dataObject.getDataObjectID()), is(false));
    }

    @Test
    public void detectsLXaip()
    {
        var dataObject = lxaip("some uri");

        assertThat(sut.isValidLXaipElement(dataObject, dataObject.getDataObjectID()), is(true));
    }

    @Test
    public void throwsOnIncompleteLXaip()
    {
        var dataObject = new DataObjectType();
        var xmlData = new AnyType();
        dataObject.setXmlData(xmlData);
        dataObject.setDataObjectID("some-id");
        var dataObjectReference = new DataObjectReferenceType();
        dataObjectReference.setURI("some uri");
        var digestMethod = new DigestMethodType();
        digestMethod.setAlgorithm("http://www.w3.org/2001/04/xmlenc#sha256");
        dataObjectReference.setDigestMethod(digestMethod);
        // digest is missing
        xmlData.getAny().add(new ObjectFactory().createDataObjectReference(dataObjectReference));

        var actual =
            assertThrows(LXaipUnprocessableException.class, () -> sut.isValidLXaipElement(dataObject, dataObject.getDataObjectID()));
        assertThat(actual.getMessage(), is("Detected a LXAIP but its data object reference (id: some-id) is incomplete"));
    }

    @Test
    public void getsBinaryData()
    {
        var dataObject = lxaip("lxaip_ok_data_object.txt", "L6N3vPvrVvHofj+V+MrUq3wwta+L7fvcJLbdoOnhGic=");

        var actual = sut.readBinaryData(dataObject, dataObject.getDataObjectID());

        assertThat(new String(actual, StandardCharsets.UTF_8), is("Dies ist ein Testdokument mit qualifizierter Signatur.\n"));
    }

    @Test
    public void throwsOnNotAllowedUri()
    {
        for (var notAllowed : List.of("../some-file.txt", "some-dir/../../some-file.txt"))
        {
            var dataObject = lxaip(notAllowed);

            var actual =
                assertThrows(LXaipUnprocessableException.class, () -> sut.readBinaryData(dataObject, dataObject.getDataObjectID()));

            assertThat(actual.getMessage(),
                containsString("LXAIP data object (id: some-id) reference uri is not allowed. Avoid using '..'"));
        }
    }

    @Test
    public void throwsOnWrongDigestValue()
    {
        var dataObject = lxaip("lxaip_ok_data_object.txt", "d3JvbmcgZGlnZXN0");

        var actual = assertThrows(LXaipDigestMismatchException.class, () -> sut.readBinaryData(dataObject, dataObject.getDataObjectID()));
        assertThat(actual.getMessage(),
            is("The calculated digest value of the LXAIP data object (id: some-id) does not match the embedded digest"));
    }

    @Test
    public void throwsOnUnknownDigestMethod()
    {
        var dataObject = lxaipUnknownAlgorithm("lxaip_ok_data_object.txt");

        var actual = assertThrows(LXaipUnprocessableException.class, () -> sut.readBinaryData(dataObject, dataObject.getDataObjectID()));
        assertThat(actual.getMessage(), is("The LXAIP digest method of the data object reference (id: some-id) is unknown"));
    }

    @Test
    public void throwsExceptionIfLXaipsDataObjectFileNotFound()
    {
        var dataObject = lxaip("does-not-exist.txt");

        var actual = assertThrows(RuntimeException.class, () -> sut.readBinaryData(dataObject, dataObject.getDataObjectID()));
        assertThat(actual.getCause(), instanceOf(IOException.class));
        assertThat(actual.getMessage(), containsString("Cannot read LXAIP's data object (id: some-id) from file"));
        assertThat(actual.getMessage(), containsString("lxaip" + File.separator + "does-not-exist.txt"));
    }

    @Test
    public void acceptsRelativeLxaipDataDirectory()
    {
        sut = new LXaipReader(Path.of("./build/resources/test/lxaip"));
        var dataObject = lxaip("lxaip_ok_data_object.txt", "L6N3vPvrVvHofj+V+MrUq3wwta+L7fvcJLbdoOnhGic=");

        var binaryData = sut.readBinaryData(dataObject, dataObject.getDataObjectID());
        assertThat(binaryData, notNullValue());
    }

    private static DataObjectType lxaip(String uri)
    {
        return lxaip(uri, "null", "http://www.w3.org/2001/04/xmlenc#sha256");
    }

    private static DataObjectType lxaip(String uri, String digest)
    {
        return lxaip(uri, digest, "http://www.w3.org/2001/04/xmlenc#sha256");
    }

    private static DataObjectType lxaipUnknownAlgorithm(String uri)
    {
        return lxaip(uri, "null", "unknown");
    }

    private static DataObjectType lxaip(String uri, String digest, String algorithm)
    {
        var dataObject = new DataObjectType();
        var xmlData = new AnyType();
        dataObject.setXmlData(xmlData);
        dataObject.setDataObjectID("some-id");
        var dataObjectReference = new DataObjectReferenceType();
        dataObjectReference.setURI(uri);
        var digestMethod = new DigestMethodType();
        digestMethod.setAlgorithm(algorithm);
        dataObjectReference.setDigestMethod(digestMethod);
        dataObjectReference.setDigestValue(Base64.decode(digest));
        xmlData.getAny().add(new ObjectFactory().createDataObjectReference(dataObjectReference));
        return dataObject;
    }
}
