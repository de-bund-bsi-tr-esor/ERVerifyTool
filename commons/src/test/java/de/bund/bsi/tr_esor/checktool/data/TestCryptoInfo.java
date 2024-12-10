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
package de.bund.bsi.tr_esor.checktool.data;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.junit.Test;


/**
 * Unit test for {@link CryptoInfo}.
 *
 * @author HMA
 */
public class TestCryptoInfo
{

    /**
     * Asserts that a {@link CryptoInfo} can be constructed, its attributes can be accessed and it can be converted to an ASN1Primitive.
     *
     * @throws Exception
     */
    @Test
    public void testCryptoInfo() throws Exception
    {
        var oid = new ASN1ObjectIdentifier("1.2.3.4.5");
        var attribute = Attribute.getInstance(new DERSequence(new ASN1Encodable[]{oid, new DERSet()}));
        var cryptoInfo = new CryptoInfo(new DERSequence(attribute));
        assertEquals(1, cryptoInfo.numberOfAttributes());
        assertThat(cryptoInfo.getAttribute(0).getAttrType(), is(oid));
        assertThat(cryptoInfo.getAttribute(1), nullValue());
        assertThat(cryptoInfo.toASN1Primitive(), instanceOf(ASN1Sequence.class));
        assertThat(((ASN1Sequence)cryptoInfo.toASN1Primitive()).iterator().next(), instanceOf(Attribute.class));
    }

    /**
     * Asserts that the {@link CryptoInfo} cannot be constructed for invalid parameters but throws a sensible exception.
     *
     * @throws Exception
     */
    @Test
    public void invalidConstruction() throws Exception
    {
        assertNoCreation(null, "Element is not an ASN1Sequence");
        assertNoCreation(ASN1Boolean.getInstance(true), "Element is not an ASN1Sequence");
        assertNoCreation(new DERSequence(), "ASN1Sequence is empty");
        assertNoCreation(new DERSequence(new DERSet()), "Element is not an Attribute");
    }

    @SuppressWarnings("unused")
    private void assertNoCreation(ASN1Object param, String exceptionMesssage)
    {
        try
        {
            new CryptoInfo(param);
            fail("expected IOException with message: " + exceptionMesssage);
        }
        catch (IOException e)
        {
            assertThat(e.getMessage(), is(exceptionMesssage));
        }
    }

}
