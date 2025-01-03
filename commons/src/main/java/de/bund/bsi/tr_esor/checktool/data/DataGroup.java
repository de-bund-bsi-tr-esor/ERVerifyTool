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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.validation.ValidatorFactory;


/**
 * Represents a data group from a hash tree.
 *
 * @author MO
 */
public class DataGroup
{

    private static final Logger LOG = LoggerFactory.getLogger(DataGroup.class);

    private static final int MASK = 0xff;

    private final String oid;

    private Collection<byte[]> hashes;

    private byte[] groupHash;

    private boolean handleHashesAsSet;

    /**
     * Constructs a new DataGroup from given hashes for given OID.
     *
     * @param hashes
     * @param oid
     */
    public DataGroup(List<byte[]> hashes, String oid)
    {
        this.hashes = new ArrayList<>(hashes);
        this.oid = oid;
    }

    /**
     * Adds the given hash to the data group.
     */
    @SuppressWarnings("PMD.NullAssignment")
    public void addHash(byte[] hash)
    {
        groupHash = null;
        hashes.add(hash);
    }

    /**
     * Whether to handle hashes in the data group as set while hashing.
     */
    public void setHandleHashesAsSet(boolean handleHashesAsSet)
    {
        this.handleHashesAsSet = handleHashesAsSet;
    }

    /**
     * Returns the hash of this data group. It is calculated by sorting and concatenating all hashes, then hashing the resulting byte
     * sequence. If this data group contains only one hash, it is returned without modification.
     */
    public byte[] getHash()
    {
        ensureHashListIsSet();
        return hashes.size() == 1 ? hashes.iterator().next() : getDoubleHash();
    }

    private void ensureHashListIsSet()
    {
        if (handleHashesAsSet && !(hashes instanceof Set<?>))
        {
            Set<byte[]> hashSet = new TreeSet<>(this::compare);
            hashSet.addAll(hashes);
            hashes = hashSet;
        }
    }

    /**
     * Same as {@link #getHash()}, but if the data group contains only one hash, it is hashed again.
     */
    public byte[] getDoubleHash()
    {
        if (groupHash == null)
        {
            ensureHashListIsSet();
            try
            {
                groupHash = ValidatorFactory.getInstance().getHashCreator().calculateHash(sortedAndConcatenatedHashes(), oid);
            }
            catch (NoSuchAlgorithmException | ReflectiveOperationException e)
            {
                LOG.error("Could not calculate hash", e);
                return null;
            }
        }
        return Arrays.copyOf(groupHash, groupHash.length);
    }

    /**
     * Checks if the original data is needed for a check of single-hashed hash. For the double-hash, the original data is never needed.
     */
    public boolean needsDataForCheck()
    {
        return hashes.size() == 1;
    }

    /**
     * The sorted and concatenated hashes of this group, source for the hash of the next partial hashtree level
     */
    public byte[] sortedAndConcatenatedHashes()
    {
        List<byte[]> hashList = new ArrayList<>(hashes);
        hashList.sort(this::compare);
        try (var concatenated = new ByteArrayOutputStream())
        {
            for (var hash : hashList)
            {
                concatenated.write(hash);
            }
            return concatenated.toByteArray();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("cannot happen on a byte array", e);
        }
    }

    private int compare(byte[] b1, byte[] b2)
    {
        for (var i = 0; i < Math.min(b1.length, b2.length); i++)
        {
            if (b1[i] != b2[i])
            {
                return (b1[i] & MASK) < (b2[i] & MASK) ? -1 : 1;
            }
        }
        if (b1.length != b2.length)
        {
            return b1.length < b2.length ? -1 : 1;
        }
        return 0;
    }


}
