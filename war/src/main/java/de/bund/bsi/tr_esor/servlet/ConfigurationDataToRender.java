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

/**
 * POJO to display configuration based values on the rendered HTML.
 *
 * @author BVO
 */
public class ConfigurationDataToRender
{

    private String configurationLoadTime;

    private String configurationUpToDate;

    private String currentProfile;

    private String verififerId;

    private String availableProfiles;

    private String errorMessage;

    private String version;

    private String pathToConfiguration;

    private String validationService;

    private String requireQualifiedTimestamps;

    private String lxaipDataDirectory;

    private String hashMode;


    /**
     * Returns the current configuration load time.
     */
    public String getConfigurationLoadTime()
    {
        return configurationLoadTime;
    }

    void setConfigurationLoadTime(String configurationLoadTime)
    {
        this.configurationLoadTime = configurationLoadTime;
    }

    /**
     * Returns "yes" if the loaded configuration is current, otherwise it returns "no".
     */
    public String getConfigurationUpToDate()
    {
        return configurationUpToDate;
    }

    void setConfigurationUpToDate(String configurationUpToDate)
    {
        this.configurationUpToDate = configurationUpToDate;
    }

    /**
     * Returns the current configured profile name.
     */
    public String getCurrentProfile()
    {
        return currentProfile;
    }

    void setCurrentProfile(String currentProfile)
    {
        this.currentProfile = currentProfile;
    }

    /**
     * Returns the current verifier id.
     */
    public String getVerififerId()
    {
        return verififerId;
    }

    void setVerififerId(String verififerId)
    {
        this.verififerId = verififerId;
    }

    /**
     * Returns a comma separated string of the available profiles.
     */
    public String getAvailableProfiles()
    {
        return availableProfiles;
    }


    void setAvailableProfiles(String availableProfiles)
    {
        this.availableProfiles = availableProfiles;
    }

    /**
     * Returns the error message.
     */
    public String getErrorMessage()
    {
        return errorMessage;
    }


    void setErrorMessage(String errorMessage)
    {
        this.errorMessage = errorMessage;
    }

    /**
     * Returns the current version.
     */
    public String getVersion()
    {
        return version;
    }


    void setVersion(String version)
    {
        this.version = version;
    }

    /**
     * Returns the current path to the configuration file.
     */
    public String getPathToConfiguration()
    {
        return pathToConfiguration;
    }


    void setPathToConfiguration(String pathToConfiguration)
    {
        this.pathToConfiguration = pathToConfiguration;
    }

    /**
     * Returns the route to reload the configuration.
     */
    public String getReloadConfigurationUrl()
    {
        return ConfigurationServlet.ROUTE_TO_RELOAD_CONFIGURATION;
    }

    /**
     * Returns hash mode.
     */
    public String getHashMode()
    {
        return hashMode;
    }

    public void setHashMode(String hashMode)
    {
        this.hashMode = hashMode;
    }

    /**
     * Returns URL to validation service.
     */
    public String getValidationService()
    {
        return validationService;
    }

    public void setValidationService(String validationService)
    {
        this.validationService = validationService;
    }

    /**
     * Returns whether qualified timestamps are required.
     */
    public String getRequireQualifiedTimestamps()
    {
        return requireQualifiedTimestamps;
    }

    public void setRequireQualifiedTimestamps(String requireQualifiedTimestamps)
    {
        this.requireQualifiedTimestamps = requireQualifiedTimestamps;
    }

    /**
     * Returns path to LXAIP directory.
     */
    public String getLxaipDataDirectory()
    {
        return lxaipDataDirectory;
    }

    public void setLxaipDataDirectory(String lxaipDataDirectory)
    {
        this.lxaipDataDirectory = lxaipDataDirectory;
    }
}
