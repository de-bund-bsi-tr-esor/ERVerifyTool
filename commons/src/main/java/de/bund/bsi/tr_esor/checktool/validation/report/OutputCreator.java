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

/**
 * Specifies that an object is able to create a report part of a certain type, mainly because its internal
 * data representation uses that type anyway.
 *
 * @author TT
 * @param <T> type of output to create
 */
public interface OutputCreator<T>
{

  /**
   * Returns an instance of target class filled with data from this object.
   */
  T getFormatted();

  /**
   * Returns the type of object created by {@link #getFormatted()}. This method my be needed because
   * instanceof can only check runtime erasure and misses the parameter type.
   */
  Class<T> getTargetClass();

}
