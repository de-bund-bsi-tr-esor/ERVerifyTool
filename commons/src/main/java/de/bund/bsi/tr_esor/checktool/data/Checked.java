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

import java.io.IOException;


/**
 * Checked casts of objects.
 *
 * @author HMA
 */
public final class Checked
{

  private final Object object;

  private Checked(Object object)
  {
    this.object = object;
  }

  /**
   * Creates a new instance for an object to be cast.
   *
   * @param object to cast
   */
  public static Checked cast(Object object)
  {
    return new Checked(object);
  }

  /**
   * Casts object of this instance and throws {@link IOException} if that is not possible, instead of a
   * {@link ClassCastException} which is no checked Exception.
   *
   * @param target
   * @throws IOException
   */
  public <T> T to(Class<T> target) throws IOException
  {
    if (object != null && !target.isInstance(object))
    {
      throw new IOException("expected instance of " + target.getSimpleName() + " but got "
                            + object.getClass().getName());
    }
    return target.cast(object);
  }

}
