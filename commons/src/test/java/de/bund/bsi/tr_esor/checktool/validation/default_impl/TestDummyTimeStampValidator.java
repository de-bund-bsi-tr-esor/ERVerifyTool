package de.bund.bsi.tr_esor.checktool.validation.default_impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.hash.LocalHashCreator;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.BsiResultMinor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;
import de.bund.bsi.tr_esor.checktool.validation.signatures.ECardResultMinor;


public class TestDummyTimeStampValidator
{

    private static byte[] correctContent = Base64.decode(
        "Bgp7V7c8oOwxO0B6YxslVn3BepntQwRfBNBK1ERQ8qZPyCsmrstH0oaMTvvjWBcyo+fLzGwu+zIGLAgXCgXuuIFNeJYrD4rCvWPa+fAT7QwH/mf7+/vBUrMKR2MEoFNduXbqspOmCKCbE6zPVwtPoif/rzoQ0wauN4JIRm0Ff+M=");

    @Test
    public void acceptsCorrectTimestampMath() throws IOException
    {
        TimeStampToken tst = loadTimeStampToken();
        var sut = new DummyTimeStampValidator();
        sut.setSourceOfRootHash(correctContent);
        var report = sut.validateInternal(new Reference("ignored"), tst);
        assertThat(report.getFormatted()
            .getSignatureOK()
            .getSigMathOK()
            .getResultMajor()).isEqualTo(ValidationResultMajor.VALID.toString());
    }

    @Test
    public void noDataToCheck() throws IOException
    {
        TimeStampToken tst = loadTimeStampToken();
        var sut = new DummyTimeStampValidator();
        var report = sut.validateInternal(new Reference("ignored"), tst);
        assertThat(report.getFormatted()
            .getSignatureOK()
            .getSigMathOK()
            .getResultMajor()).isEqualTo(ValidationResultMajor.INDETERMINED.toString());
        assertThat(report.getFormatted()
            .getSignatureOK()
            .getSigMathOK()
            .getResultMinor()).isEqualTo(ECardResultMinor.DETACHED_SIGNATURE_WITHOUT_E_CONTENT);
    }

    @Test
    public void detectsTimestampHashNotMatchingData() throws IOException
    {
        TimeStampToken tst = loadTimeStampToken();
        var sut = new DummyTimeStampValidator();
        sut.setSourceOfRootHash("ERROR".getBytes(StandardCharsets.UTF_8));
        var report = sut.validateInternal(new Reference("ignored"), tst);
        assertThat(report.getFormatted()
            .getSignatureOK()
            .getSigMathOK()
            .getResultMajor()).isEqualTo(ValidationResultMajor.INVALID.toString());
        assertThat(report.getFormatted()
            .getSignatureOK()
            .getSigMathOK()
            .getResultMinor()).isEqualTo(BsiResultMinor.HASH_VALUE_MISMATCH.getUri());
        assertThat(report.getFormatted().getSignatureOK().getSigMathOK().getResultMessage().getValue()).contains(
            "does not match the calculated root hash value of the partial hashtree");
    }

    @Test
    public void detectsTimestampHashNotMatchingSignature() throws Exception
    {
        // Set hash of other content in timestamp, but don't change signature bytes
        TimeStampToken tst = loadTimeStampToken();
        var encoded = tst.getEncoded();
        var hashValueInTimestamp = tst.getTimeStampInfo().getMessageImprintDigest();
        var positionOfHashInEncoded = findBytesInEncodedTimestamp(encoded, hashValueInTimestamp);
        var hashedContent = "ERROR".getBytes(StandardCharsets.UTF_8);
        var hashValue =
            new LocalHashCreator().calculateHash(hashedContent, tst.getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId());
        System.arraycopy(hashValue, 0, encoded, positionOfHashInEncoded, hashValue.length);

        var sut = new DummyTimeStampValidator();
        sut.setSourceOfRootHash(hashedContent);
        var report = sut.validateInternal(new Reference("ignored"), new TimeStampToken(new CMSSignedData(encoded)));
        assertThat(report.getFormatted()
            .getSignatureOK()
            .getSigMathOK()
            .getResultMajor()).isEqualTo(ValidationResultMajor.INVALID.toString());
        assertThat(report.getFormatted().getSignatureOK().getSigMathOK().getResultMinor()).isEqualTo(ECardResultMinor.INVALID_SIGNATURE);
        assertThat(report.getFormatted().getSignatureOK().getSigMathOK().getResultMessage().getValue()).contains(
            "Validation of the mathematical correctness of the given timestamp failed");
    }

    @Test
    public void detectsSignatureManipulated() throws Exception
    {
        TimeStampToken tst = loadTimeStampToken();
        var encoded = tst.getEncoded();
        var signature = tst.toCMSSignedData().getSignerInfos().iterator().next().getSignature();
        var positionOfSignatureInEncoded = findBytesInEncodedTimestamp(encoded, signature);
        encoded[positionOfSignatureInEncoded]++;

        var sut = new DummyTimeStampValidator();
        sut.setSourceOfRootHash(correctContent);
        var report = sut.validateInternal(new Reference("ignored"), new TimeStampToken(new CMSSignedData(encoded)));
        assertThat(report.getFormatted()
            .getSignatureOK()
            .getSigMathOK()
            .getResultMajor()).isEqualTo(ValidationResultMajor.INVALID.toString());
        assertThat(report.getFormatted().getSignatureOK().getSigMathOK().getResultMinor()).isEqualTo(ECardResultMinor.INVALID_SIGNATURE);
        assertThat(report.getFormatted().getSignatureOK().getSigMathOK().getResultMessage().getValue()).contains(
            "Validation of the mathematical correctness of the given timestamp failed");
    }

    @Test
    public void detectsManipulatedCertificate() throws Exception
    {
        TimeStampToken tst = loadTimeStampToken();
        var encoded = tst.getEncoded();
        var certSignature = tst.toCMSSignedData().getSignerInfos().getSigners().iterator().next().getSignature();
        var positionOfCertSignatureInEncoded = findBytesInEncodedTimestamp(encoded, certSignature);
        encoded[positionOfCertSignatureInEncoded]++;

        var sut = new DummyTimeStampValidator();
        sut.setSourceOfRootHash(correctContent);
        var report = sut.validateInternal(new Reference("ignored"), new TimeStampToken(new CMSSignedData(encoded)));

        assertThat(report.getFormatted()
            .getSignatureOK()
            .getSigMathOK()
            .getResultMajor()).isEqualTo(ValidationResultMajor.INVALID.toString());
        assertThat(report.getFormatted().getSignatureOK().getSigMathOK().getResultMinor()).isEqualTo(ECardResultMinor.INVALID_SIGNATURE);
        assertThat(report.getFormatted().getSignatureOK().getSigMathOK().getResultMessage().getValue()).contains(
            "Validation of the mathematical correctness of the given timestamp failed");
    }

    private int findBytesInEncodedTimestamp(byte[] timestamp, byte[] content)
    {
        var extracted = new byte[content.length];
        for (int i = 0; i < (timestamp.length - content.length); i++)
        {
            System.arraycopy(timestamp, i, extracted, 0, content.length);
            if (Arrays.equals(extracted, content))
            {
                return i;
            }
        }
        return -1;
    }

    private TimeStampToken loadTimeStampToken() throws IOException
    {
        var exampleEr = TestUtils.decodeTestResource("/bin/example.ers.b64");
        var parsed = new ASN1EvidenceRecordParser().parse(exampleEr);
        var tst = parsed.getAtss().get(0).get(0).getTimeStampToken();
        return tst;
    }

}
