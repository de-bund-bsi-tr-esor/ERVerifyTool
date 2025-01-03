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
package de.bund.bsi.tr_esor.checktool.hash;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.assertj.core.api.Assertions;
import org.junit.Test;


/**
 * Tests the HashCreator implementation.
 *
 * @author MO, BVO
 */
public class HashCreatorTest
{

    /**
     * Tests local hash creator with SHA-1, SHA-256 and SHA-512, with hash values calculated by OpenSSL.
     *
     * @throws Exception
     */
    @Test
    public void testHashing() throws Exception
    {
        var testData = "Something to hash".getBytes(StandardCharsets.UTF_8);
        HashCreator hashCreator = new LocalHashCreator();
        var sha1hash = hashCreator.calculateHash(testData, "1.3.14.3.2.26"); // SHA1
        var sha256hash = hashCreator.calculateHash(testData, "2.16.840.1.101.3.4.2.1"); // SHA256
        var sha512hash = hashCreator.calculateHash(testData, "2.16.840.1.101.3.4.2.3"); // SHA512
        var expectedSha1hash = Base64.getDecoder().decode("YAdYMOObfFeKOweBAemmaPaNHCg=");
        var expectedSha256hash = Base64.getDecoder().decode("KiM2HJ3YhN10kF0+7S4MkwIgEZjzZSmgNDhLdIqpGes=");
        var expectedSha512hash =
            Base64.getDecoder().decode("yChVyfMAZHt5A2vxLek1TDhVHmRg3E/2aKpHX0L+kiz/9HyR6APIrEbaaM8DtVuzDN+F7McDSbVr1z9MaT22VQ==");
        assertThat("SHA1 hash", sha1hash, is(expectedSha1hash));
        assertThat("SHA256 hash", sha256hash, is(expectedSha256hash));
        assertThat("SHA512 hash", sha512hash, is(expectedSha512hash));
    }

    /**
     * Tests that an unsupported OID results in a NoSuchAlgorithmException.
     *
     * @throws Exception
     */
    @Test
    public void testUnsupportedOID() throws Exception
    {
        var testData = "Something to hash".getBytes(StandardCharsets.UTF_8);
        HashCreator hashCreator = new LocalHashCreator();
        Assertions.assertThatExceptionOfType(NoSuchAlgorithmException.class)
            .isThrownBy(() -> hashCreator.calculateHash(testData, "1.3.3.7.1"))
            .withMessage("1.3.3.7.1 MessageDigest not available");
    }
}
