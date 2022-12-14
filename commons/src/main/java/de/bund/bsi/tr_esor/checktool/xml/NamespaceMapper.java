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
package de.bund.bsi.tr_esor.checktool.xml;

import java.util.HashMap;
import java.util.Map;

import org.w3c.dom.Element;


/**
 * Mapper for XAIP XML name space prefixes.
 *
 * @author MO
 */
public class NamespaceMapper
{

  private static final Map<String, String> DEFAULT_NS_PREFIX_MAP = new HashMap<>();

  static
  {
    DEFAULT_NS_PREFIX_MAP.put("http://www.bsi.bund.de/tr-esor/xaip", "xaip");
    DEFAULT_NS_PREFIX_MAP.put("http://www.w3.org/2001/XMLSchema", "xs");
    DEFAULT_NS_PREFIX_MAP.put("http://www.w3.org/2000/09/xmldsig#", "ds");
    DEFAULT_NS_PREFIX_MAP.put("http://uri.etsi.org/01903/v1.3.2#", "xades");
    DEFAULT_NS_PREFIX_MAP.put("urn:ietf:params:xml:ns:ers", "ers");
    DEFAULT_NS_PREFIX_MAP.put("urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#", "vr");
    DEFAULT_NS_PREFIX_MAP.put("urn:oasis:names:tc:dss:1.0:core:schema", "dss");
    DEFAULT_NS_PREFIX_MAP.put("http://www.bsi.bund.de/ecard/api/1.1", "ec");
    DEFAULT_NS_PREFIX_MAP.put("urn:oasis:names:tc:SAML:2.0:assertion", "saml");
  }

  private final Map<String, String> nsPrefixMap;

  /**
   * Constructs a name space mapper using given map
   *
   * @param configured
   */
  public NamespaceMapper(Map<String, String> configured)
  {
    nsPrefixMap = new HashMap<>(DEFAULT_NS_PREFIX_MAP);
    var tnsSet = false;
    for ( var entry : configured.entrySet() )
    {
      var isTargetNamespace = entry.getValue() == null || entry.getValue().isEmpty();
      if (tnsSet && isTargetNamespace)
      {
        throw new IllegalArgumentException("Only one targetNamespace (empty namespace prefix) may be defined in the configuration!");
      }
      tnsSet = tnsSet || isTargetNamespace;
      nsPrefixMap.put(entry.getKey(), entry.getValue());
    }
  }

  /**
   * Reconstructs the namespace prefixes in a given element. When creating elements from JAXB objects, there
   * is no prefix defined. We manipulate the element because JAXB would require the usage of a class from
   * package com.sun.* to create the prefixes during marshaling.
   *
   * @param element
   */
  public void setNSPrefixRecursively(Element element)
  {
    if (nsPrefixMap.containsKey(element.getNamespaceURI()))
    {
      setNSPrefix(element);
    }
    var children = element.getChildNodes().getLength();
    for ( var i = 0 ; i < children ; i++ )
    {
      var child = element.getChildNodes().item(i);
      if (child instanceof Element)
      {
        setNSPrefixRecursively((Element)child);
      }
    }
  }

  void setNSPrefix(Element element)
  {
    var prefix = nsPrefixMap.get(element.getNamespaceURI());
    element.setPrefix(prefix);
    element.removeAttribute("xmlns");
    element.setAttributeNS("http://www.w3.org/2000/xmlns/",
                           prefix == null || prefix.isEmpty() ? "xmlns" : "xmlns:" + prefix,
                           element.getNamespaceURI());
  }
}
