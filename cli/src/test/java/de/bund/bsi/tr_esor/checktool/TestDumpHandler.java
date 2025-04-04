package de.bund.bsi.tr_esor.checktool;

import static org.mockito.Mockito.mock;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.out.OutputFolder;
import de.bund.bsi.tr_esor.checktool.parser.XaipParser;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


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
            var lXaipReader = mock(LXaipReader.class);
            var xaipParser = new XaipParser(lXaipReader);
            xaipParser.setInput(ins);
            var xaipAndSerializer = xaipParser.parse();
            sut.dumpXaip(xaipAndSerializer.getXaip(), xaipAndSerializer.getSerializer(), lXaipReader, "any");
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
    public void lXaipToFolder() throws Exception
    {
        TestUtils.loadDefaultConfig();

        try (InputStream ins = TestUtils.class.getResourceAsStream("/lxaip/lxaip_ok_er_cred.xml"))
        {
            var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory("https://tools.ietf.org/html/rfc4998"));
            var xaipParser = new XaipParser(lXaipReader);
            xaipParser.setInput(new ByteArrayInputStream(ins.readAllBytes()));
            var xaipAndSerializer = xaipParser.parse();
            sut.dumpXaip(xaipAndSerializer.getXaip(),
                xaipAndSerializer.getSerializer(),
                lXaipReader,
                "https://tools.ietf.org/html/rfc4998");
        }
        final var aoid_folder = "0cd5ec81_b123_4024_b1cc_d20a32dca014";
        assertFolderExists(aoid_folder);
        assertFolderExists(aoid_folder + "/D0_V001");
        assertFolderExists(aoid_folder + "/CT_V001");

        assertFileExists(aoid_folder + "/D0_V001/D0_V001.bin");
        assertFileExists(aoid_folder + "/CT_V001/D0_V001.bin");
        assertFileExists(aoid_folder + "/CT_V001/signature.dat");

        assertFileContainsBytes(aoid_folder + "/D0_V001/D0_V001.bin", "PNG".getBytes(StandardCharsets.US_ASCII));
        assertFileContainsBytes(aoid_folder + "/CT_V001/D0_V001.bin", "PNG".getBytes(StandardCharsets.US_ASCII));
        assertFileContainsBytes(aoid_folder + "/CT_V001/signature.dat", "Governikus CA".getBytes(StandardCharsets.US_ASCII));
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
            sut.dumpXaip(xaipAndSerializer.getXaip(),
                xaipAndSerializer.getSerializer(),
                mock(LXaipReader.class),
                "https://tools.ietf.org/html/rfc4998");
        }
        assertFolderExists("no_aoid");
    }

    @Test
    public void reportToFolder() throws Exception
    {
        sut.dumpReport(mock(VerificationReportType.class));
        assertFileExists("no_aoid/report.xml");
    }

    @Test
    public void reportToAoidFolder() throws Exception
    {
        outputFolder.createAoidFolder("aoid");
        sut.dumpReport(mock(VerificationReportType.class));
        assertFileExists("aoid/report.xml");
    }
}
