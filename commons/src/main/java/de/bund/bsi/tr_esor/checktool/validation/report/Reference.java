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
package de.bund.bsi.tr_esor.checktool.validation.report;

import java.util.Arrays;
import java.util.Objects;


/**
 * Describes which object within an object tree is validated. Contains at least a human readable "field name".
 * May contain further information which is more suitable for instance in an XML verification report.
 *
 * @author HMA, TT
 */
public class Reference
{

  private final Reference parent;

  private final String name;

  private byte[] signatureValue;

  private String xPath;

  private Reference(Reference parent, String name)
  {
    this.parent = parent;
    this.name = name;
  }

  /**
   * Creates a new top-level reference.
   *
   * @param name
   */
  public Reference(String name)
  {
    this(null, name);
  }

  /**
   * Creates new sub-reference.
   *
   * @param childName describes position within the parent
   */
  public Reference newChild(String childName)
  {
    return new Reference(this, childName);
  }

  /**
   * Returns a signature value identifying the referenced object (if known).
   */
  public byte[] getSignatureValue()
  {
    return signatureValue == null ? null : Arrays.copyOf(signatureValue, signatureValue.length);
  }

  /**
   * Specifies a signature value of the addressed object (in case it is some kind of signature).
   */
  public void setSignatureValue(byte[] signatureValue)
  {
    this.signatureValue = Arrays.copyOf(signatureValue, signatureValue.length);
  }

  /**
   * Returns the xPath of the referenced object (optional).
   */
  public String getxPath()
  {
    return xPath;
  }

  /**
   * @see #getxPath()
   */
  public void setxPath(String xPath)
  {
    this.xPath = xPath;
  }

  /**
   * Returns <code>true</code> if the given reference belongs to the sub tree starting at this reference.
   *
   * @param other
   */
  public boolean isAncestorOf(Reference other)
  {
    var intermediate = other;
    while (true)
    {
      if (intermediate == null)
      {
        return false;
      }
      if (intermediate.equals(this))
      {
        return true;
      }
      intermediate = intermediate.parent;
    }
  }

  /**
   * Returns a string describing where the other object is relative to this reference.
   *
   * @param anchestor
   */
  public String relativize(Reference anchestor)
  {
    var result = toString();
    if (anchestor.isAncestorOf(this))
    {
      var other = anchestor.toString();
      return other.equals(result) ? "" : result.substring(other.length() + 1);
    }
    return result;
  }

  /**
   * Returns the full name starting at top-level.
   */
  @Override
  public String toString()
  {
    return parent == null ? name : parent + "/" + name;
  }

  @Override
  public int hashCode()
  {
    return ((name == null) ? 0 : name.hashCode()) + 31 * ((parent == null) ? 0 : parent.hashCode());
  }

  /**
   * We consider the reference as uniquely defined by its name and parent and do not consider additional
   * optional attributes here.
   */
  @Override
  public boolean equals(Object obj)
  {
    if (this == obj)
    {
      return true;
    }
    if (obj == null || getClass() != obj.getClass())
    {
      return false;
    }
    var other = (Reference)obj;
    return Objects.equals(name, other.name) && Objects.equals(parent, other.parent);
  }

}
