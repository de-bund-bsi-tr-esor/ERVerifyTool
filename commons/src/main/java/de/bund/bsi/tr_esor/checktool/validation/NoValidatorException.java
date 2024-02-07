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
package de.bund.bsi.tr_esor.checktool.validation;

/**
 * Exception to be thrown if a validator cannot be created.
 *
 * @author BVO, TT
 */
public class NoValidatorException extends RuntimeException
{

    private static final long serialVersionUID = 1534755707417005771L;

    /**
     * Creates new instance for problem with configured class.
     *
     * @param className of validator
     * @param cause
     */
    public NoValidatorException(String className, ReflectiveOperationException cause)
    {
        super("cannot instantiate " + className + " because of " + cause.getMessage(), cause);
    }

    /**
     * Creates new instance for unsupported arguments.
     *
     * @param targetClass class name of target class of validator
     * @param ctx context of validator
     * @param reportClass class name of report part of validator
     */
    public NoValidatorException(String targetClass, ValidationContext<?> ctx, String reportClass)
    {
        super("no validator found for " + targetClass + ", context is " + ctx.getClass() + ", required report type " + reportClass);
    }
}
