package de.bund.bsi.tr_esor.checktool.validation.default_impl;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import java.util.Base64;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.bouncycastle.asn1.ASN1Primitive;
import org.junit.BeforeClass;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.HashSortingMode;
import de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp;
import de.bund.bsi.tr_esor.checktool.data.DigestsToCover;
import de.bund.bsi.tr_esor.checktool.validation.ErValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Test class for ArchiveTimestampValidator unit tests
 */
public class TestArchiveTimeStampValidator
{

    public static final String SHA512OID = "2.16.840.1.101.3.4.2.3";

    private final String[] correctHashes = {"/HXeepzwb9jFSycx4qDgxcS32H8jijbCv0DWlHruz8HZHEayaxrnIFGKOWwckchkhQ8VwGkNjS5WIATH4No1vw==",
        "Dnr9zOJqykmADqlR6YWbr3AoIvWkTQhXpkgisJQM16CqkGoDnDggdMTPO8Kli7ER8buppe4K9vv8WKp48SZX1w==",
        "tsJRXIKugf921ZgSyQT0yqT0v0F0F3WgtBI6E0BycL0l/qoI/yh9gYBdyTgsJKFKot8WxIdjMk+vm/4W8Xcs1w=="};

    private final String[] alternativeHashes = {"F2nQab78tN1ju3X0Ya4PV6MB/z9NFcSzy7EqFscEk8uIK1Mif4Jjt9VCe5cMFpPckOA6R1+SO8JtUmhxSJaDsg==",
        "Dnr9zOJqykmADqlR6YWbr3AoIvWkTQhXpkgisJQM16CqkGoDnDggdMTPO8Kli7ER8buppe4K9vv8WKp48SZX1w==",
        "tsJRXIKugf921ZgSyQT0yqT0v0F0F3WgtBI6E0BycL0l/qoI/yh9gYBdyTgsJKFKot8WxIdjMk+vm/4W8Xcs1w=="};


    /**
     * Load test configuration
     */
    @BeforeClass
    public static void prepare() throws Exception
    {
        TestUtils.loadDefaultConfig();
    }

    /**
     * Asserts that in the HashSortingMode.BOTH the correct hashes can be present in the DigestsToCover both as primary and as alternative
     * hashes.
     */
    @Test
    public void acceptsBothHashmodes() throws Exception
    {
        // Set the correct hashes as primary
        var sut = new ArchiveTimeStampValidator();
        var ats = readArchiveTimeStamp();
        sut.setContext(createContext(ats));
        sut.setDigestsToCover(createDigestsToCover(false, HashSortingMode.BOTH), SHA512OID);
        var report = sut.validate(new Reference("dummy"), ats);
        assertThat(report.getOverallResult().getResultMajor(), is(ValidationResultMajor.INDETERMINED.toString()));
        assertThat(report.getSummarizedMessage(), containsString("no online validation of time stamp done"));
        assertThat(report.getSummarizedMessage(), not(containsString("do not match the mode")));
        assertThat(report.getSummarizedMessage(), not(containsString("Missing digest")));

        // Set the correct hashes as alternative
        sut = new ArchiveTimeStampValidator();
        sut.setContext(createContext(ats));
        sut.setDigestsToCover(createDigestsToCover(true, HashSortingMode.BOTH), SHA512OID);
        report = sut.validate(new Reference("dummy"), ats);
        assertThat(report.getOverallResult().getResultMajor(), is(ValidationResultMajor.INDETERMINED.toString()));
        assertThat(report.getSummarizedMessage(), containsString("no online validation of time stamp done"));
        assertThat(report.getSummarizedMessage(), not(containsString("do not match the mode")));
        assertThat(report.getSummarizedMessage(), not(containsString("Missing digest")));
    }

    /**
     * Asserts that in the HashSortingMode.UNSORTED when the correct (sorted) hashes are present as alternative hashes in the
     * DigestsToCover, a clear message is generated.
     */
    @Test
    public void handlesAlternativeHashes() throws Exception
    {
        var sut = new ArchiveTimeStampValidator();
        var ats = readArchiveTimeStamp();
        sut.setContext(createContext(ats));
        sut.setDigestsToCover(createDigestsToCover(false, HashSortingMode.UNSORTED), SHA512OID);
        var report = sut.validate(new Reference("dummy"), ats);
        assertThat(report.getOverallResult().getResultMajor(), is(ValidationResultMajor.INDETERMINED.toString()));
        assertThat(report.getSummarizedMessage(), containsString("no online validation of time stamp done"));
        assertThat(report.getSummarizedMessage(),
            containsString("The hashes present in the evidence record do not match the mode (sorted/unsorted) given by the configuration."));
        assertThat(report.getSummarizedMessage(), containsString("The hashes present seem to conform to the sorted hash mode."));
        assertThat(report.getSummarizedMessage(), not(containsString("Missing digest")));
    }

    /**
     * Asserts that in the HashSortingMode.SORTD when the correct (sorted) hashes are present as primard hashes in the DigestsToCover, no
     * warning is generated.
     */
    @Test
    public void handlesCorrectAlternative() throws Exception
    {
        var sut = new ArchiveTimeStampValidator();
        var ats = readArchiveTimeStamp();
        sut.setContext(createContext(ats));
        sut.setDigestsToCover(createDigestsToCover(false, HashSortingMode.SORTED), SHA512OID);
        var report = sut.validate(new Reference("dummy"), ats);
        assertThat(report.getOverallResult().getResultMajor(), is(ValidationResultMajor.INDETERMINED.toString()));
        assertThat(report.getSummarizedMessage(), containsString("no online validation of time stamp done"));
        assertThat(report.getSummarizedMessage(), not(containsString("do not match the mode")));
        assertThat(report.getSummarizedMessage(), not(containsString("Missing digest")));
    }

    private ErValidationContext createContext(ArchiveTimeStamp ats) throws ReflectiveOperationException
    {
        var context = new ErValidationContext(new Reference("dummy"), null, null, null, false);
        context.setSecureData(ats, new GregorianCalendar(2021, Calendar.JANUARY, 1).getTime());
        context.setDeclaredDigestOIDs(List.of("2.16.840.1.101.3.4.2.3"));
        return context;
    }

    private ArchiveTimeStamp readArchiveTimeStamp() throws Exception
    {
        var atsBytes = TestUtils.decodeTestResource("/sorted/ArchiveTimeStamp_sorted.b64");
        return new ArchiveTimeStamp(ASN1Primitive.fromByteArray(atsBytes));
    }

    private DigestsToCover createDigestsToCover(boolean exchangeHashes, HashSortingMode hashSortingMode)
    {
        Map<Reference, byte[]> correct = new HashMap<>();
        for (var hash : correctHashes)
        {
            correct.put(new Reference(UUID.randomUUID().toString()), Base64.getDecoder().decode(hash));
        }
        Map<Reference, byte[]> alternative = new HashMap<>();
        for (var hash : alternativeHashes)
        {
            alternative.put(new Reference(UUID.randomUUID().toString()), Base64.getDecoder().decode(hash));
        }
        if (!exchangeHashes)
        {
            return new DigestsToCover(correct, alternative, false, hashSortingMode);
        }
        else
        {
            return new DigestsToCover(alternative, correct, false, hashSortingMode);
        }
    }
}
