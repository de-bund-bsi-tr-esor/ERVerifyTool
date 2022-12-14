package de.bund.bsi.tr_esor.checktool.parser;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.data.UnsupportedData;


public class TestUnsupportedXaipParser
{

  @Test
  public void testEsor11XAIP() throws IOException
  {
    var sut = new UnsupportedXaipParser();
    var testFile = TestUtils.class.getResourceAsStream("/xaip/esor11/xaip_ok.xml");
    sut.setInput(testFile);
    assertTrue(sut.canParse());
    assertTrue(sut.parse() instanceof UnsupportedData);
  }

  @Test
  public void testEsor12XAIP() throws IOException
  {
    var sut = new UnsupportedXaipParser();
    var testFile = TestUtils.class.getResourceAsStream("/xaip/esor12/xaip_ok.xml");
    sut.setInput(testFile);
    assertTrue(sut.canParse());
    assertTrue(sut.parse() instanceof UnsupportedData);
  }

  @Test
  public void testEsor13XAIP() throws IOException
  {
    var sut = new UnsupportedXaipParser();
    var testFile = TestUtils.class.getResourceAsStream("/xaip/xaip_ok.xml");
    sut.setInput(testFile);
    assertFalse(sut.canParse());
  }

  @Test
  public void testOtherXML() throws IOException
  {
    var sut = new UnsupportedXaipParser();
    var testFile = TestUtils.class.getResourceAsStream("/config.xml");
    sut.setInput(testFile);
    assertFalse(sut.canParse());
  }

  @Test
  public void testBin() throws IOException
  {
    var sut = new UnsupportedXaipParser();
    var testFile = TestUtils.class.getResourceAsStream("/bin/basis_ers.b64");
    sut.setInput(testFile);
    assertFalse(sut.canParse());
  }
}
