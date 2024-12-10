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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Optional;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.xml.bind.JAXBException;


/**
 * Shows the current configuration and can reload the current configuration.
 *
 * @author BVO
 */
public class ConfigurationServlet extends HttpServlet
{

    static final String ROUTE_TO_RELOAD_CONFIGURATION = "loadConfiguration";

    private static final Logger LOG = LoggerFactory.getLogger(ConfigurationServlet.class);

    private static final long serialVersionUID = 1L;

    private static final Path CONFIG_DIR = Path.of(System.getenv("CATALINA_BASE"), "conf");

    private static final String OUTPUT_YES = "yes";

    private static final String OUTPUT_NO = "no";

    static Path configFile = CONFIG_DIR.resolve("ErVerifyTool.xml");

    private static Date configLoad = null;

    private static boolean configLoadedFromWar = false;

    private static String version;

    private static String errorMessage = "";

    private final SimpleDateFormat df = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss", Locale.GERMANY);

    /**
     * Initializes the Servlet.
     */
    @Override
    public void init() throws ServletException
    {
        if (version == null)
        {
            setVersion(getVersionFromManifest());
        }
        setupLogging();
        if (System.getenv("CATALINA_BASE") == null)
        {
            LOG.warn("Environment variable CATALINA_BASE is not set.");
        }

        loadConfiguration();
        super.init();
    }

    /**
     * Renders the configuration HTML page if the configuration can be loaded. If the requested path equals
     * {@link #ROUTE_TO_RELOAD_CONFIGURATION} the configuration will be reloaded.
     */
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        var path = req.getServletPath();
        if (path.endsWith("/" + ROUTE_TO_RELOAD_CONFIGURATION))
        {
            loadConfiguration();
        }
        var fetchData = fetchData();
        try
        {
            resp.getWriter()
                .println(configLoad == null ? CreateHtml.forErrorPage(fetchData) : CreateHtml.forConfigurationOverview(fetchData));
        }
        catch (IOException e)
        {
            LOG.error("Cannot get response writer", e);
        }
    }

    private ConfigurationDataToRender fetchData()
    {
        var result = new ConfigurationDataToRender();
        result.setVersion(version == null ? "unknown" : version);
        if (configLoadedFromWar)
        {
            String message = String.format(
                "The configuration has been loaded from the application war file. To load a configuration from a file place it in %s",
                configFile.toAbsolutePath());
            result.setPathToConfiguration(message);
        }
        else
        {
            result.setPathToConfiguration(configFile.toAbsolutePath().toString());
        }
        result.setErrorMessage(errorMessage);
        if (configLoad != null)
        {
            var configuration = Configurator.getInstance();
            var profileName = configuration.getDefaultProfileName();

            result.setConfigurationLoadTime(df.format(configLoad));
            result.setConfigurationUpToDate(configLoad.after(new Date(configFile.toFile().lastModified())) ? OUTPUT_YES : OUTPUT_NO);
            result.setCurrentProfile(profileName);
            result.setVerififerId(configuration.getVerifierID());
            var availableProfiles = configuration.getSupportedProfileNames().toString();
            result.setAvailableProfiles(availableProfiles.substring(1, availableProfiles.length() - 1));
            result.setHashMode(configuration.hashSortingMode(profileName).toString().toLowerCase(Locale.getDefault()));
            result.setValidationService(Optional.ofNullable(configuration.getVerificationServiceURL(profileName))
                .orElse("(not configured)"));
            result.setRequireQualifiedTimestamps(configuration.requiresQualifiedTimestamps(profileName) ? OUTPUT_YES : OUTPUT_NO);
            result.setLxaipDataDirectory(configuration.getLXaipDataDirectory(profileName).toString());
        }
        return result;
    }

    @SuppressWarnings("PMD.NullAssignment")
    private void loadConfiguration()
    {
        try (InputStream stream = loadConfigurationFromFileOrClasspath(configFile))
        {
            Configurator.getInstance().load(stream);

            configLoad = new Date();
            errorMessage = "";
            LOG.info("Configuration loaded");
        }
        catch (JAXBException | ReflectiveOperationException | IOException e)
        {
            configLoad = null;
            errorMessage =
                Optional.ofNullable(e.getMessage()).orElse(Optional.ofNullable(e.getCause()).map(c -> c.getMessage()).orElse(""));
            LOG.error("Failed to load configuration", e);
        }
    }

    private InputStream loadConfigurationFromFileOrClasspath(Path config)
    {
        try
        {
            var ins = Files.newInputStream(config);
            configLoadedFromWar = false;
            return ins;
        }
        catch (IOException e)
        {
            var message = String.format("Cannot load configuration file from %s, using configuration from class path instead.", config);
            LOG.warn(message);
            configLoadedFromWar = true;
            return loadConfigFromClasspath();
        }
    }

    protected InputStream loadConfigFromClasspath()
    {
        return Thread.currentThread().getContextClassLoader().getResourceAsStream("ErVerifyTool.xml");
    }


    private static void setupLogging()
    {
        var file = CONFIG_DIR.resolve("log4j2.xml").toFile().getAbsoluteFile();
        if (file.canRead())
        {
            try (var context = (LoggerContext)LogManager.getContext(false))
            {
                context.setConfigLocation(file.toURI());
                LOG.debug("Logging configuration loaded from {}", file);
            }
        }
        else
        {
            System.err.println("Cannot read logging configuration " + file.getAbsolutePath());
        }
    }

    private String getVersionFromManifest()
    {
        String result = null;
        var props = new Properties();
        try
        {
            props.load(getServletContext().getResourceAsStream("/META-INF/MANIFEST.MF"));
            result = props.getProperty("Implementation-Version");
        }
        catch (IOException e)
        {
            LOG.error("Failed to load version", e);
        }
        return result;
    }

    private static void setVersion(String version)
    {
        ConfigurationServlet.version = version;
    }

}
