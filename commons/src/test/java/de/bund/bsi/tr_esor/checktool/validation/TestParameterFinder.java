package de.bund.bsi.tr_esor.checktool.validation;

import static org.mockito.Mockito.mock;

import java.io.IOException;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.entry.ParameterFinder;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.parser.XaipParser;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;


/**
 * Provides input data.
 */
class TestParameterFinder extends ParameterFinder
{

    TestParameterFinder(String profileName)
    {
        super();
        handleProfileName(profileName);
        returnVerificationReport = TestUtils.createReturnVerificationReport();
    }

    TestParameterFinder()
    {
        super();
        handleProfileName(null);
        returnVerificationReport = TestUtils.createReturnVerificationReport();
    }

    public void setEr(String path) throws IOException
    {
        er = new ASN1EvidenceRecordParser().parse(TestUtils.decodeTestResource(path));
        erRef = new Reference("ER_TEST_VALUE");
    }

    public void setXaip(String path) throws Exception
    {
        try (var ins = TestErValidation.class.getResourceAsStream(path))
        {
            var parser = new XaipParser(mock(LXaipReader.class));
            parser.setInput(ins);
            var xas = parser.parse();
            xaip = xas.getXaip();
            serializer = xas.getSerializer();
        }
        xaipRef = new Reference("XAIP_TEST_VALUE");
    }
}
