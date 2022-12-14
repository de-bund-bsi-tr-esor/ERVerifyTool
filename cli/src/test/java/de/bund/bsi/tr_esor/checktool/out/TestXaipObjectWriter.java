package de.bund.bsi.tr_esor.checktool.out;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import oasis.names.tc.dss._1_0.core.schema.AnyType;

import jakarta.activation.DataHandler;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Element;

import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.signatures.DetachedSignatureValidationContext;
import de.bund.bsi.tr_esor.checktool.xml.ComprehensiveXaipSerializer;
import de.bund.bsi.tr_esor.xaip.BinaryDataType;
import de.bund.bsi.tr_esor.xaip.DataObjectType;


/**
 * Unit test for class {@link XaipObjectWriter}.
 *
 * @author PRE
 */
public class TestXaipObjectWriter extends FileOutputChecker
{

  /**
   * XML Test Element //CHECKSTYLE:OFF
   *
   * <pre>
   * {@literal <parent>}
   *   {@literal <child1 />}
   *   {@literal <child2 />}
   * {@literal </parent>}
   * </pre>
   *
   * //CHECKSTYLE:ON
   */
  private Element xmlTestNode;

  /**
   * <b>Canonicalizer Instance</b><br>
   * http://www.w3.org/TR/2001/REC-xml-c14n-20010315
   */
  private Canonicalizer canonicalizer;

  /**
   * {@literal <destination>/<no_aoid>}
   */
  private OutputFolder outFolder;

  /**
   * Initialize {@link #xmlTestNode} and {@link #canonicalizer} and {@link #outFolder}.
   */
  @Before
  public void before() throws ParserConfigurationException, InvalidCanonicalizerException, IOException
  {
    var docFactory = DocumentBuilderFactory.newInstance();
    docFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    var docBuilder = docFactory.newDocumentBuilder();
    var doc = docBuilder.newDocument();
    var parentNode = doc.createElement("parent");
    var childNode1 = doc.createElement("child1");
    parentNode.appendChild(childNode1);
    var childNode2 = doc.createElement("child2");
    parentNode.appendChild(childNode2);
    xmlTestNode = parentNode;

    if (!Init.isInitialized())
    {
      Init.init();
    }
    canonicalizer = Canonicalizer.getInstance("http://www.w3.org/TR/2001/REC-xml-c14n-20010315");

    outFolder = new OutputFolder(destination).createAoidFolder("no_aoid");
  }

  /**
   * Check if null makes no trouble for {@link DataObjectType} signature.
   */
  @Test
  public void testWriteWithNullForDataObject()
  {
    new XaipObjectWriter().withOutputFolder(new OutputFolder(destination)).write((DataObjectType)null);
  }

  /**
   * Check if null makes no trouble for {@link DetachedSignatureValidationContext} signature.
   */
  @Test
  public void testWriteWithNullForContext()
  {
    new XaipObjectWriter().withOutputFolder(new OutputFolder(destination))
                          .write((DetachedSignatureValidationContext)null);
  }

  /**
   * Check if data object with binary data is written correctly.
   */
  @Test
  public void testWriteWithBinary() throws Exception
  {
    var content = "nice test content";

    var xaipSerializer = mock(ComprehensiveXaipSerializer.class);
    when(xaipSerializer.serialize(any())).thenReturn(content.getBytes(StandardCharsets.US_ASCII));

    var dataHandler = new DataHandler(content.getBytes(StandardCharsets.US_ASCII), "text/plain");
    var binaryContent = new BinaryDataType();
    binaryContent.setValue(dataHandler);

    var data = new DataObjectType();
    data.setDataObjectID("testWriteWithBinary");
    data.setBinaryData(binaryContent);

    new XaipObjectWriter().withOutputFolder(outFolder).withXaipSerializer(xaipSerializer).write(data);

    var writtenFile = "no_aoid/testWriteWithBinary/testWriteWithBinary.bin";
    assertFileExists(writtenFile);
    assertFileContains(writtenFile, content);
  }

  /**
   * Check if data object with xml data is written correctly.
   */
  @Test
  public void testWriteWithXml() throws Exception
  {
    var xmlContent = new AnyType();
    xmlContent.getAny().add(xmlTestNode);

    var xaipSerializer = mock(ComprehensiveXaipSerializer.class);
    when(xaipSerializer.serialize(any())).thenReturn(canonicalize(xmlTestNode));

    var data = new DataObjectType();
    data.setDataObjectID("testWriteWithXml");
    data.setXmlData(xmlContent);

    new XaipObjectWriter().withOutputFolder(outFolder).withXaipSerializer(xaipSerializer).write(data);

    var writtenFile = "no_aoid/testWriteWithXml/testWriteWithXml.xml";
    assertFileExists(writtenFile);
    assertFileContains(writtenFile, "<parent><child1></child1><child2></child2></parent>");
  }

  /**
   * Check if content of detached signature context is written correctly.
   */
  @Test
  public void testWriteWithContext() throws Exception
  {
    var content = "nice test content";

    Map<Reference, byte[]> proctectedDataById = new HashMap<>();

    var credentialReference = new Reference("testWriteWithContext");
    credentialReference.setSignatureValue(new byte[]{65, 66, 67, 68, 69, 70});
    var ctx = new DetachedSignatureValidationContext(credentialReference, null, proctectedDataById, null);

    var binaryRef = new Reference("binaryData");
    proctectedDataById.put(binaryRef, content.getBytes(StandardCharsets.US_ASCII));
    ctx.setPreferredExtension(binaryRef, ".bin");

    var xmlRef = new Reference("xmlData");
    proctectedDataById.put(xmlRef, canonicalize(xmlTestNode));
    ctx.setPreferredExtension(xmlRef, ".xml");

    new XaipObjectWriter().withOutputFolder(outFolder).write(ctx);

    var writtenSignature = "no_aoid/testWriteWithContext/signature.dat";
    assertFileExists(writtenSignature);
    assertFileContains(writtenSignature, "ABCDEF");

    var writtenBinary = "no_aoid/testWriteWithContext/binaryData.bin";
    assertFileExists(writtenBinary);
    assertFileContains(writtenBinary, content);

    var writtenXml = "no_aoid/testWriteWithContext/xmlData.xml";
    assertFileExists(writtenXml);
    assertFileContains(writtenXml, "<parent><child1></child1><child2></child2></parent>");
  }

  /**
   * Check if nasty ids escaped correctly.
   */
  @Test
  public void testWriteWithContextAndNastyIds() throws Exception
  {
    var content = "nice test content";

    Map<Reference, byte[]> proctectedDataById = new HashMap<>();

    var credentialReference = new Reference("../..");
    var ctx = new DetachedSignatureValidationContext(credentialReference, null, proctectedDataById, null);

    var binaryRef = new Reference("../hehe/id");
    proctectedDataById.put(binaryRef, content.getBytes(StandardCharsets.US_ASCII));
    ctx.setPreferredExtension(binaryRef, ".bin");

    new XaipObjectWriter().withOutputFolder(outFolder).write(ctx);

    var writtenBinary = "no_aoid/_____/.._hehe_id.bin";
    assertFileExists(writtenBinary);
    assertFileContains(writtenBinary, content);
  }

  private byte[] canonicalize(Element node) throws CanonicalizationException
  {
    var out = new ByteArrayOutputStream();
    canonicalizer.canonicalizeSubtree(node, out);
    return out.toByteArray();
  }

}
