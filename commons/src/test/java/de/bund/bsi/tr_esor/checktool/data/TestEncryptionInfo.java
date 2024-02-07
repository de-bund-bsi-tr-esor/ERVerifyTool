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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.junit.Test;


/**
 * Unit test for {@link EncryptionInfo}.
 *
 * @author HMA
 */
public class TestEncryptionInfo
{

    /**
     * Asserts that the {@link EncryptionInfo} can be constructed and converted to an ASN1Primitive.
     *
     * @throws Exception
     */
    @Test
    public void testCryptoInfo() throws Exception
    {
        var encryptionInfo = new EncryptionInfo("1.2.3.4.5", new DERSet().toASN1Primitive().getEncoded());
        var primitive = encryptionInfo.toASN1Primitive();
        assertThat(primitive, instanceOf(DERSequence.class));
        var iterator = ((DERSequence)primitive).iterator();
        assertThat(iterator.next(), is(new ASN1ObjectIdentifier("1.2.3.4.5")));
        assertThat(iterator.next(), is(new DEROctetString(new DERSet())));
        assertFalse(iterator.hasNext());
    }

    /**
     * Asserts that the {@link EncryptionInfo} cannot be constructed for invalid parameters but throws a sensible exception.
     *
     * @throws Exception
     */
    @Test
    public void invalidConstruction() throws Exception
    {
        assertNoCreation(null);
        assertNoCreation(ASN1Boolean.getInstance(true));
        assertNoCreation(new DERSequence());
        assertNoCreation(new DERSequence(new DERSet()));
    }

    @SuppressWarnings("unused")
    private void assertNoCreation(ASN1Object param)
    {
        try
        {
            new EncryptionInfo(param);
            fail("expected IOException");
        }
        catch (IOException e)
        {
            assertThat(e.getMessage(), is("not valid (EI-1)"));
        }
    }

}
