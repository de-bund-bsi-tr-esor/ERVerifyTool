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
package de.bund.bsi.tr_esor.checktool.validation.default_impl.basis.ers;

import org.junit.Test;

import de.bund.bsi.tr_esor.checktool.validation.ValidationResultMajor;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.AlgorithmUsageValidator;
import de.bund.bsi.tr_esor.checktool.validation.default_impl.TestAlgorithmUsageValidator;


/**
 * Unit test for {@link BasisErsAlgorithmUsageValidator}. It covers also the test cases of {@link TestAlgorithmUsageValidator} which must be
 * hold by this test too.
 *
 * @author HMA
 */
public class TestBasisErsAlgorithmUsageValidator extends TestAlgorithmUsageValidator
{

    /**
     * Asserts that hmacWithSHA256 is not suitable for {@link BasisErsAlgorithmUsageValidator} but for {@link AlgorithmUsageValidator}.
     *
     * @throws Exception
     */
    @Test
    public void testBasisErsProfileRestriction() throws Exception
    {
        final var hmacWithSHA256 = "1.2.840.113549.2.9";
        checkAlgorithm(createValidatorUnderTest(), hmacWithSHA256, ValidationResultMajor.INVALID, "/algorithm#hashAlgorithmNotSuitable");
        checkAlgorithm(new AlgorithmUsageValidator(), hmacWithSHA256, ValidationResultMajor.VALID, null);

    }

    @Override
    protected AlgorithmUsageValidator createValidatorUnderTest()
    {
        return new BasisErsAlgorithmUsageValidator();
    }

}
