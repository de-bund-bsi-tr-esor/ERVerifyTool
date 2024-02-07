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
package de.bund.bsi.tr_esor.servlet;

import java.beans.BeanInfo;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Utility class to parse a HTML template and replace the known placeholders.
 *
 * @author BVO
 */
public final class CreateHtml
{

    private static final Logger LOG = LoggerFactory.getLogger(CreateHtml.class);

    private static BeanInfo beanInfo;

    static
    {
        try
        {
            beanInfo = Introspector.getBeanInfo(ConfigurationDataToRender.class);
        }
        catch (IntrospectionException e)
        {
            LOG.error("can not introspect ConfigurationDataToRender", e);
        }
    }

    private CreateHtml()
    {
        // Utility class
    }

    /**
     * Reads the config&#46;html template out of the resource folder and replaces all matching placeholders.
     *
     * @param dataToRender POJO filled with displayable configuration data
     * @return the parsed config.html
     */
    public static String forConfigurationOverview(ConfigurationDataToRender dataToRender)
    {
        return createHtml("/config.html", dataToRender);
    }


    /**
     * Reads the error&#46;html template out of the resource folder and replaces all matching placeholders.
     *
     * @param data POJO filled with displayable configuration data
     * @return the parsed error.html
     */
    public static String forErrorPage(ConfigurationDataToRender data)
    {
        return createHtml("/error.html", data);
    }

    private static String createHtml(String resource, ConfigurationDataToRender data)
    {

        try (var ins = CreateHtml.class.getResourceAsStream(resource);
            var t = new Scanner(ins, "utf-8"))
        {
            var html = t.useDelimiter("\\A").next();
            var readableProperties = Arrays.asList(beanInfo.getPropertyDescriptors())
                .stream()
                .filter(pd -> pd.getReadMethod() != null)
                .collect(Collectors.toList());
            for (var property : readableProperties)
            {
                var val = invokeValueFromConfigurationData(data, property);
                var replacement = "";
                if (val instanceof String)
                {
                    replacement = ((String)val).replace("\\", "\\\\");
                }
                html = html.replaceAll("\\{\\{" + property.getName() + "\\}\\}", replacement);
            }
            return html;
        }
        catch (IOException e)
        {
            LOG.error("can not read " + resource + " from resources", e);
        }

        return "";
    }

    private static Object invokeValueFromConfigurationData(ConfigurationDataToRender data, PropertyDescriptor property)
    {
        try
        {
            return property.getReadMethod().invoke(data);
        }
        catch (ReflectiveOperationException e)
        {
            LOG.error("can not invoke " + property.getName(), e);
        }
        return null;
    }

}
