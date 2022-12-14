package de.bund.bsi.tr_esor.checktool;

import static org.mockito.Mockito.mock;

import java.io.InputStream;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;

import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.out.OutputFolder;
import de.bund.bsi.tr_esor.checktool.parser.XaipParser;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;


public class TestDumpHandler extends FileOutputChecker
{

  private DumpHandler sut;

  private OutputFolder outputFolder;

  @Before
  public void setUp() throws Exception
  {
    super.setUp();
    outputFolder = new OutputFolder(destination);
    sut = new DumpHandler(outputFolder);
  }

  /**
   * Given a valid XAIP with a signature, make sure signed document is written to output folder.
   */
  @Test
  public void xaipContentToFiles() throws Exception
  {

    try (InputStream ins = TestDumpHandler.class.getResourceAsStream("/xaip_ok_sig.xml"))
    {
      var xaipParser = new XaipParser(mock(LXaipReader.class));
      xaipParser.setInput(ins);
      var xaipAndSerializer = xaipParser.parse();
      sut.dumpXaip(xaipAndSerializer.getXaip(), xaipAndSerializer.getSerializer());
    }
    assertFolderExists("xaip_ok_sig");
    assertFolderExists("xaip_ok_sig/detachedSignature");
    assertFolderExists("xaip_ok_sig/DO_01");
    assertFolderExists("xaip_ok_sig/DO_02");

    assertFileExists("xaip_ok_sig/DO_01/DO_01.bin");
    assertFileExists("xaip_ok_sig/DO_02/DO_02.bin");
    assertFileExists("xaip_ok_sig/detachedSignature/DO_01.bin");
    assertFileExists("xaip_ok_sig/detachedSignature/signature.dat");
  }

  /**
   * Given a valid XAIP with a signature, make sure signed document is written to output folder.
   */
  @Test
  public void xaipToNoAoidFolder() throws Exception
  {
    try (InputStream ins = TestDumpHandler.class.getResourceAsStream("/xaip_ok_sig.xml"))
    {
      var xaipParser = new XaipParser(mock(LXaipReader.class));
      xaipParser.setInput(ins);
      var xaipAndSerializer = xaipParser.parse();
      var xaip = xaipAndSerializer.getXaip();
      xaip.getPackageHeader().setAOID(null);
      sut.dumpXaip(xaipAndSerializer.getXaip(), xaipAndSerializer.getSerializer());
    }
    assertFolderExists("no_aoid");
  }

  @Test
  public void reportToFolder() throws Exception
  {
    sut.dumpReport(mock(VerificationReportType.class));
    assertFileExists("report.xml");
  }

  @Test
  public void reportToAoidFolder() throws Exception
  {
    outputFolder.createAoidFolder("aoid");
    sut.dumpReport(mock(VerificationReportType.class));
    assertFileExists("aoid/report.xml");
  }
}
