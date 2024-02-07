package de.bund.bsi.tr_esor.checktool.validation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.nullValue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.entry.FileParameterFinder;
import de.bund.bsi.tr_esor.checktool.entry.InputPreparator;
import de.bund.bsi.tr_esor.checktool.entry.ParameterFinder;

import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Tests for the timestamp online verification done by the ECardTimestampValidator. This requires a chain of validators to work together, so
 * these tests must be applied to an early entrypoint of the overall validation and cannot be tested in isolation of the
 * ECardTimestampValidator.
 */
public class TestEROnlineValidationIT
{

    private TestParameterFinder params;

    @BeforeClass
    public static void setUpStatic() throws Exception
    {
        TestUtils.loadDefaultConfig();
    }

    @Before
    public void setUp() throws Exception
    {
        params = new TestParameterFinder("custom");
    }

    @Test
    public void erWithCommonTimestamp() throws Exception
    {
        params.setXaip("/xaip/xaip_ok_ers.xml");

        var report = validate(params);
        assertValidForER(report);
    }

    @Test
    public void erWithCommonlyResignedTimestamp() throws Exception
    {
        params.setXaip("/xaip/xaip_ok_er_resigned.xml");

        var report = validate(params);
        assertValidForER(report);
    }

    @Test
    public void erWithTimestampFromSingleProtectedData() throws Exception
    {
        params.setXaip("/xaip/xaip_ok_single_protected_data_object.xml");

        var report = validate(params);
        assertValidForER(report);
    }

    @Test
    public void erWithTimestampsFromResignedSingleProtectedData() throws Exception
    {
        params.setXaip("/xaip/xaip_ok_single_protected_data_object_resigned.xml");

        var report = validate(params);
        assertValidForER(report);
    }

    @Test
    public void erWithTimestampsFromResignedAndRehasedSingleProtectedData() throws Exception
    {
        params.setXaip("/xaip/xaip_ok_single_protected_data_object_resigned_and_rehased.xml");

        var report = validate(params);
        assertValidForER(report);
    }

    @Test
    public void erWithTimestampsFromResignedAndRehasedAndAgainResignedSingleProtectedData() throws Exception
    {
        params.setXaip("/xaip/xaip_ok_single_protected_data_object_resigned_and_rehased_and_resigned.xml");

        var report = validate(params);
        assertValidForER(report);
    }

    @Test
    public void erWithTimestampsCommonlyResignedAndRehased() throws Exception
    {
        params.setXaip("/xaip/xaip_ok_resigned_and_rehashed.xml");

        var report = validate(params);
        assertValidForER(report);
    }

    @Test
    public void erWithoutDataAndTimestampFromSingleProtectedData() throws Exception
    {
        var fileParams = fileParameterFinder(null, "./xaip/xaip_ok_single_protected_data_object.er.xml");

        var report = validate(fileParams);
        var result = report.getIndividualReport().get(0).getResult();
        assertThat(result.getResultMajor(), endsWith(":InsufficientInformation"));
        assertThat(result.getResultMessage().getValue(),
            allOf(containsString("atss/0: no protected data to check"), containsString("detached_content_file_missing")));
    }

    private static FileParameterFinder fileParameterFinder(Path protectedData, String er) throws URISyntaxException, IOException
    {
        return new FileParameterFinder(protectedData,
            Path.of(TestEROnlineValidationIT.class.getClassLoader().getResource(er).toURI()),
            "custom");
    }

    private static void assertValidForER(VerificationReportType report)
    {
        var evidenceReport = report.getIndividualReport()
            .stream()
            .filter(irt -> irt.getSignedObjectIdentifier().getFieldName().contains("ER"))
            .findAny()
            .get();
        var result = evidenceReport.getResult();
        assertThat(result.getResultMajor(), endsWith(":Success"));
        assertThat(result.getResultMessage(), nullValue());
    }

    private VerificationReportType validate(ParameterFinder p) throws ReflectiveOperationException, IOException
    {
        return ValidationScheduler.validate(new InputPreparator(p).getValidations());
    }

}
