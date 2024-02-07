/*-
 * Copyright (c) 2018
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

import de.bund.bsi.tr_esor.checktool.xml.ComprehensiveXaipSerializer;
import de.bund.bsi.tr_esor.xaip.XAIPType;


/**
 * Wraps a XAIP together with a serializer for its elements. Needed to avoid the "two return values problem".
 */
public class XaipAndSerializer
{

    private final XAIPType xaip;

    private final ComprehensiveXaipSerializer serializer;


    /**
     * Create a wrapper for a XAIP and the serializer used to serialize its contents
     */
    public XaipAndSerializer(XAIPType xaip, ComprehensiveXaipSerializer serializer)
    {
        this.xaip = xaip;
        this.serializer = serializer;
    }

    /**
     * Returns the wrapped XAIP.
     */
    public XAIPType getXaip()
    {
        return xaip;
    }

    /**
     * Returns the serializer which is suitable for the elements in the wrapped XAIP.
     */
    public ComprehensiveXaipSerializer getSerializer()
    {
        return serializer;
    }
}
