/*-
 * Copyright (c) 2017
 * Federal Office for Information Security (BSI),
 * Godesberger Allee 185-189,
 * 53175 Bonn, Germany,
 * phone: +49 228 99 9582-0,
 * fax: +49 228 99 9582-5400,
 * e-mail: bsi@bsi.bund.de
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.bund.bsi.tr_esor.checktool.validation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.TestUtils;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage;
import de.bund.bsi.tr_esor.checktool.data.EvidenceRecord;
import de.bund.bsi.tr_esor.checktool.hash.HashCreator;
import de.bund.bsi.tr_esor.checktool.hash.LocalHashCreator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.AlgorithmUsageValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.EvidenceRecordValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers.BasisErsAlgorithmUsageValidator;
import de.bund.bsi.tr_esor.checktool.validation.report.AlgorithmValidityReport;
import de.bund.bsi.tr_esor.checktool.validation.report.EvidenceRecordReport;
import de.bund.bsi.tr_esor.checktool.validation.report.Reference;


/**
 * Unit test for {@link ValidatorFactory}.
 *
 * @author HMA, TT
 */
public class TestValidatorFactory
{

    private final ValidatorFactory systemUnderTest = ValidatorFactory.getInstance();

    private ValidationContext<?> context;

    /**
     * Loads special configuration which contains several exception cases.
     *
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception
    {
        TestUtils.loadConfig("/configForTestingFactory.xml");
        context = new ErValidationContext(new Reference("dummyReference"), (EvidenceRecord)null, ProfileNames.RFC4998, null, true);
    }

    /**
     * Resets configuration to continue normal testing.
     *
     * @throws Exception
     */
    @AfterClass
    public static void tearDownClass() throws Exception
    {
        TestUtils.loadDefaultConfig();
    }

    /**
     * Asserts that a hash creator instance can be configured in configuration.
     *
     * @throws Exception
     */
    @Test
    public void canGetHashCreator() throws Exception
    {
        assertThat("HashCreator instance from test config", systemUnderTest.getHashCreator(), instanceOf(OtherHashCreator.class));
        TestUtils.loadDefaultConfig();
        assertThat("HashCreator instance from empty config", systemUnderTest.getHashCreator(), instanceOf(LocalHashCreator.class));
    }

    /**
     * Asserts that the validator factory will provide expected validators for a predefined profile.
     */
    @Test
    public void testShippedProfile() throws Exception
    {
        Validator<AlgorithmUsage, ?, AlgorithmValidityReport> val =
            systemUnderTest.getValidator(AlgorithmUsage.class, AlgorithmValidityReport.class, context);
        assertThat("for RFC4998", val.getClass().getName(), is(AlgorithmUsageValidator.class.getName()));

        var c2 = new ErValidationContext(new Reference("dummyReference"), (EvidenceRecord)null, ProfileNames.BASIS_ERS, null, true);
        val = systemUnderTest.getValidator(AlgorithmUsage.class, AlgorithmValidityReport.class, c2);
        assertThat("for Basis", val.getClass().getName(), is(BasisErsAlgorithmUsageValidator.class.getName()));
    }

    /**
     * Asserts that the validator factory will provide the configured validators for a configured profile.
     */
    @Test
    public void testConfiguredProfile() throws Exception
    {
        // in default profile that validator cannot be constructed.
        ValidationContext<?> otherContext =
            new ErValidationContext(new Reference("dummy"), (EvidenceRecord)null, "test_profile", null, true);
        assertThat(systemUnderTest.getValidator(EvidenceRecord.class, EvidenceRecordReport.class, otherContext),
            instanceOf(OtherErValidator.class));
    }

    /**
     * Asserts that the validator factory recognizes built-in and configured profile names.
     */
    @Test
    public void testSupportedProfiles() throws Exception
    {
        assertTrue(systemUnderTest.isProfileSupported(ProfileNames.RFC4998));
        assertTrue(systemUnderTest.isProfileSupported(ProfileNames.BASIS_ERS));
        assertTrue(systemUnderTest.isProfileSupported("test_profile"));
        assertFalse(systemUnderTest.isProfileSupported("unknown"));
    }

    /**
     * Special HashCreator class. Do not use otherwise.
     */
    public static class OtherHashCreator implements HashCreator
    {

        @Override
        public byte[] calculateHash(byte[] data, String oid) throws NoSuchAlgorithmException
        {
            return "Just for testing".getBytes(StandardCharsets.UTF_8);
        }
    }

    /**
     * Special validator class. Do not use otherwise.
     */
    public static class OtherErValidator extends EvidenceRecordValidator
    {
        // nothing
    }
}
