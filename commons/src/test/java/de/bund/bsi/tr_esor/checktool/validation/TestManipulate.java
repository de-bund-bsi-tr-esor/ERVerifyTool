package de.bund.bsi.tr_esor.checktool.validation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.encoders.Base64;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.data.DataGroup;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;


/**
 * Utility Class for creating XAIP testdata.
 */
public class TestManipulate
{

    public static final Logger LOG = LoggerFactory.getLogger(TestManipulate.class);

    /**
     * Loads configuration.
     */
    @BeforeClass
    public static void setUpStatic() throws Exception
    {
        TestUtils.loadDefaultConfig();
    }

    /**
     * Utility function to create a XAIP with intermediate hash. Precondition: Hash Tree with at least two levels in the partial hash tree,
     * to create a hash from the first level and include it into the second. Used to create xaip_ok_ers_intermediate_hash.xml.
     */
    @Test
    // @Ignore
    public void addIntermediateHashToHashTree() throws Exception
    {
        var params = new TestParameterFinder();
        params.setXaip("/xaip/xaip_ok_ers_intermediate_hash.xml");
        var xaip = params.getXaip();
        var er = xaip.getCredentialsSection().getCredential().get(2).getEvidenceRecord();
        var asn1 = new ASN1EvidenceRecordParser().parse(er.getAsn1EvidenceRecord());
        var partialHashTree0 = asn1.getAtss().get(0).get(0).getPartialHashtree(0);
        var dataGroup = new DataGroup(partialHashTree0, "2.16.840.1.101.3.4.2.1");
        asn1.getAtss().get(0).get(0).getPartialHashtree(1).add(dataGroup.getHash());
        er.setAsn1EvidenceRecord(toASN1Sequence(asn1).getEncoded());
        LOG.info(new String(Base64.encode(er.getAsn1EvidenceRecord()), StandardCharsets.UTF_8));
    }

    /**
     * Utility function to create a broken XAIP with intermediate Hash. Precondition: Hash Tree with at least two levels in the partial hash
     * tree, to create a hash from the first level and include it into the second. Used to create xaip_nok_ers_wrong_intermediate_hash.xml;
     */
    @Test
    @Ignore
    public void addBrokenHashIntoHashTree() throws Exception
    {
        var params = new TestParameterFinder();
        params.setXaip("/xaip/xaip_nok_ers_wrong_intermediate_hash.xml");
        var xaip = params.getXaip();
        var er = xaip.getCredentialsSection().getCredential().get(2).getEvidenceRecord();
        var asn1 = new ASN1EvidenceRecordParser().parse(er.getAsn1EvidenceRecord());
        var dataGroup = new DataGroup(List.of("bla".getBytes(StandardCharsets.UTF_8)), "2.16.840.1.101.3.4.2.1");
        asn1.getAtss().get(0).get(0).getPartialHashtree(1).add(dataGroup.getHash());
        er.setAsn1EvidenceRecord(toASN1Sequence(asn1).getEncoded());
        LOG.info(new String(Base64.encode(er.getAsn1EvidenceRecord()), StandardCharsets.UTF_8));
    }

    /**
     * generate an evidence record
     */
    public ASN1Sequence toASN1Sequence(EvidenceRecord evidenceRecord) throws IOException
    {
        var v = new ASN1EncodableVector();
        v.add(new ASN1Integer(evidenceRecord.getVersion()));

        var encodableVector = new ASN1EncodableVector();
        for (String hashAlgo : evidenceRecord.getDigestAlgorithms())
        {
            var o = new ASN1ObjectIdentifier(hashAlgo);
            encodableVector.add(new AlgorithmIdentifier(o, DERNull.INSTANCE));
        }
        v.add(new DLSequence(encodableVector));

        if (evidenceRecord.getCryptoInfo() != null)
        {
            ASN1TaggedObject t = new DLTaggedObject(false, 0, evidenceRecord.getCryptoInfo().toASN1Primitive());
            v.add(t);
        }
        if (evidenceRecord.getEncryptionInfo() != null)
        {
            ASN1TaggedObject t = new DLTaggedObject(false, 1, evidenceRecord.getEncryptionInfo().toASN1Primitive());
            v.add(t);
        }
        v.add(evidenceRecord.getAtss().toASN1Primitive());
        return new DLSequence(v);
    }
}
