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
package de.bund.bsi.tr_esor.checktool.conf;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.Objects;


/**
 * Finds out the generic type arguments of a class. Note that the type arguments may by anywhere in the object
 * hierarchy and may even change sequence. Thats why we look only for the one matching some known base class.
 *
 * @author TT
 */
public class TypeAnalyzer
{

  private final Class<?> clazz;

  /**
   * Creates new instance for given class.
   *
   * @param clazz
   */
  public TypeAnalyzer(Class<?> clazz)
  {
    this.clazz = clazz;
  }

  /**
   * Analyzing interfaces and type hierarchy, return the first generic type argument (value) which is the
   * specified class or a subclass of it.
   *
   * @param scope base class of parameter type to search
   * @return null if the class is not generic for specified argument
   */
  public <T> Class<? extends T> getFirstMatchingTypeArgument(Class<T> scope)
  {
    Class<?> intermediate = clazz;
    Class<? extends T> result = null;
    while (result == null && intermediate != null)
    {
      result = getParameterTypeExtending(intermediate.getGenericSuperclass(), scope);
      if (result != null)
      {
        break;
      }
      for ( Type interf : intermediate.getGenericInterfaces() )
      {
        result = getParameterTypeExtending(interf, scope);
        if (result != null)
        {
          break;
        }
      }
      intermediate = intermediate.getSuperclass();
    }
    return result;
  }

  @SuppressWarnings("unchecked")
  private <T> Class<? extends T> getParameterTypeExtending(Type o, Class<T> parameterType)
  {
    if (o instanceof ParameterizedType)
    {
      return Arrays.stream(((ParameterizedType)o).getActualTypeArguments())
                   .map(this::getClass)
                   .filter(Objects::nonNull)
                   .filter(parameterType::isAssignableFrom)
                   .findFirst()
                   .orElse(null);
    }
    return null;
  }

  @SuppressWarnings("rawtypes")
  private Class getClass(Type x)
  {
    if (x instanceof Class)
    {
      return (Class)x;
    }
    if (x instanceof ParameterizedType)
    {
      return (Class)((ParameterizedType)x).getRawType();
    }
    return null;
  }
}
