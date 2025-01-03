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

import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import de.bund.bsi.tr_esor.checktool._1.ConfigurableObjectType;
import de.bund.bsi.tr_esor.checktool._1.Configuration;
import de.bund.bsi.tr_esor.checktool._1.ConfiguredObjectsCollection;
import de.bund.bsi.tr_esor.checktool._1.NamespacePrefixType;
import de.bund.bsi.tr_esor.checktool._1.ObjectFactory;
import de.bund.bsi.tr_esor.checktool._1.ParameterType;
import de.bund.bsi.tr_esor.checktool._1.ParserType;
import de.bund.bsi.tr_esor.checktool._1.ProfileType;
import de.bund.bsi.tr_esor.checktool._1.ValidatorType;
import de.bund.bsi.tr_esor.checktool.validation.NoValidatorException;
import de.bund.bsi.tr_esor.checktool.validation.ValidationContext;
import de.bund.bsi.tr_esor.checktool.validation.Validator;
import de.bund.bsi.tr_esor.checktool.validation.report.ReportPart;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Unmarshaller;


/**
 * Reads the configuration file and provides values in named methods.
 * <p>
 * Before using methods to get configuration values the method {@link #load(InputStream)} has to be called successfully.
 *
 * @author TT
 */
public final class Configurator
{

    private static final Logger LOG = LoggerFactory.getLogger(Configurator.class);

    private static final Configurator INSTANCE = new Configurator();

    private Configuration config;

    private ValidatorRepository validators;

    /**
     * for tests only
     */
    Configurator()
    {
        // Singleton
    }

    /**
     * Singleton getter.
     */
    public static Configurator getInstance()
    {
        return INSTANCE;
    }

    /**
     * Loads the configuration from given input.
     */
    @SuppressWarnings("PMD.NullAssignment")
    public void load(InputStream ins) throws JAXBException, ReflectiveOperationException
    {
        try
        {
            var ctx = JAXBContext.newInstance(ObjectFactory.class.getPackage().getName());
            var u = ctx.createUnmarshaller();
            var schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            setSchemaForUnmarshaller(u, schemaFactory);
            var x = u.unmarshal(ins);
            config = (Configuration)x;
            validators = new ValidatorRepository();
            if (config.getGeneral().getConfiguredObjects() != null)
            {
                addToRepo(config.getGeneral().getConfiguredObjects(), null);
            }
            for (var profile : config.getProfile())
            {
                addToRepo(profile, profile.getName());
            }
            if (!isProfileSupported(getDefaultProfileName()))
            {
                throw new ReflectiveOperationException("Value of DefaultProfileName does not match any supported profile.");
            }
        }
        catch (JAXBException | ReflectiveOperationException | RuntimeException e)
        {
            config = null;
            throw e;
        }
    }

    private void setSchemaForUnmarshaller(Unmarshaller u, SchemaFactory schemaFactory)
    {
        try
        {
            u.setSchema(schemaFactory.newSchema(new StreamSource(getClass().getResourceAsStream("/Config.xsd"))));
        }
        catch (SAXException e)
        {
            LOG.error("Failed to load schema, no schema validation available", e);
        }
    }

    private void addToRepo(ConfiguredObjectsCollection collection, String profileName) throws ReflectiveOperationException
    {
        for (var val : collection.getValidator())
        {
            var validatorClass = Class.forName(val.getClassName().trim());
            var targetClass = Class.forName(val.getTargetType().trim());
            var genTypes = assertIsValidatorForTarget(validatorClass, targetClass);
            assertConstructorPresent(validatorClass, val.getParameter().isEmpty());

            validators.addToProfile(() -> createInstance(val, validatorClass),
                targetClass,
                genTypes.getFirstMatchingTypeArgument(ValidationContext.class),
                genTypes.getFirstMatchingTypeArgument(ReportPart.class),
                profileName);
        }
    }

    private static <T> T createInstance(ConfigurableObjectType cnf, Class<T> clazz)
    {
        var params = cnf.getParameter().stream().collect(Collectors.toMap(ParameterType::getName, ParameterType::getValue));
        try
        {
            return createNewMapInstance(clazz, params);
        }
        catch (ReflectiveOperationException e)
        {
            throw new NoValidatorException(clazz.getName(), e);
        }
    }

    private static <T> T createNewMapInstance(Class<T> clazz, Map<String, String> params)
        throws InstantiationException, IllegalAccessException, InvocationTargetException, NoSuchMethodException
    {
        try
        {
            return clazz.getConstructor(Map.class).newInstance(params);
        }
        catch (NoSuchMethodException e)
        {
            if (!params.isEmpty())
            {
                throw e;
            }
            return clazz.getDeclaredConstructor().newInstance();
        }
    }

    private void assertConstructorPresent(Class<?> validatorClass, boolean paramsEmpty) throws ReflectiveOperationException
    {
        if (paramsEmpty)
        {
            try
            {
                validatorClass.getConstructor();
                return;
            }
            catch (NoSuchMethodException e)
            {
                LOG.debug("Validator class does not have a constructor with empty parameter, assuming it takes a map", e);
            }
        }
        try
        {
            validatorClass.getConstructor(Map.class);
        }
        catch (NoSuchMethodException e)
        {
            throw new ReflectiveOperationException("Missing constructor with Map parameter in class: " + validatorClass.getName(), e);
        }
    }

    private static TypeAnalyzer assertIsValidatorForTarget(Class<?> clazz, Class<?> targetClass) throws ReflectiveOperationException
    {
        if (!Validator.class.isAssignableFrom(clazz))
        {
            throw new ReflectiveOperationException("Configured class does not extend Validator: " + clazz.getName());
        }
        var genTypes = new TypeAnalyzer(clazz);
        if (genTypes.getFirstMatchingTypeArgument(targetClass) == null)
        {
            throw new ReflectiveOperationException("Validator "
                + clazz.getName()
                + " does not comply with target class: "
                + targetClass.getName());
        }
        return genTypes;
    }

    /**
     * Returns <code>true</code> if profile is configured.
     */
    public boolean isProfileSupported(String profileName)
    {
        assertConfigLoaded();
        return getSupportedProfileNames().contains(profileName);
    }

    /**
     * Returns the configured verifier ID.
     */
    public String getVerifierID()
    {
        assertConfigLoaded();
        return config.getGeneral().getVerifierID();
    }

    /**
     * Returns the configured instance of a hash creator.
     */
    public ConfigurableObjectType getHashCreator()
    {
        assertConfigLoaded();
        return config.getGeneral().getHashCreator();
    }

    /**
     * Returns the name of the default profile.
     */
    public String getDefaultProfileName()
    {
        assertConfigLoaded();
        return config.getGeneral().getDefaultProfileName().trim();
    }

    /**
     * Returns the name space prefixes to use for XML elements.
     */
    public Map<String, String> getXMLNSPrefixes()
    {
        assertConfigLoaded();
        return config.getGeneral()
            .getNamespacePrefix()
            .stream()
            .collect(Collectors.toMap(NamespacePrefixType::getNamespace, NamespacePrefixType::getValue));
    }

    /**
     * Returns the name space prefixes to use for XML elements.
     */
    public void addXMLNSPrefix(String namespace, String prefix)
    {
        assertConfigLoaded();
        var namespacePrefix = new NamespacePrefixType();
        namespacePrefix.setNamespace(namespace);
        namespacePrefix.setValue(prefix);
        config.getGeneral().getNamespacePrefix().add(namespacePrefix);
    }

    /**
     * Returns a list of supported profiles.
     */
    public List<String> getSupportedProfileNames()
    {
        assertConfigLoaded();
        var result = config.getProfile().stream().map(ProfileType::getName).collect(Collectors.toList());
        for (var profile : ProfileNames.getPredefinedProfileNames())
        {
            if (result.stream().noneMatch(profile::equals))
            {
                result.add(profile);
            }
        }
        return result;
    }

    /**
     * Returns the parser configurations for specified profile.
     */
    public List<ParserType> getParsers(String name)
    {
        assertConfigLoaded();
        return config.getProfile()
            .stream()
            .filter(p -> name.equals(p.getName()))
            .map(ProfileType::getParser)
            .findAny()
            .orElse(Collections.emptyList());
    }

    /**
     * Returns the validator configurations for specified profile.
     */
    public List<ValidatorType> getValidators(String name)
    {
        assertConfigLoaded();
        return config.getProfile()
            .stream()
            .filter(p -> name.equals(p.getName()))
            .map(ProfileType::getValidator)
            .findAny()
            .orElse(Collections.emptyList());
    }

    /**
     * Returns the general parser configurations.
     */
    public List<ParserType> getParsers()
    {
        assertConfigLoaded();
        return Optional.ofNullable(config.getGeneral().getConfiguredObjects())
            .map(ConfiguredObjectsCollection::getParser)
            .orElse(Collections.emptyList());
    }

    /**
     * @return whether the hashes should be sorted (according to RFC 4998) or should be unsorted (according to RFC 6283) for a certain
     *     profile, or if both is allowed.
     */
    public HashSortingMode hashSortingMode(String profileName)
    {
        assertConfigLoaded();
        var profile = getProfile(profileName);
        if (profile != null)
        {
            return HashSortingMode.fromString(profile.getHashMode());
        }
        return HashSortingMode.DEFAULT;
    }

    /**
     * @return the LXAIP data directory, may be null
     */
    public Path getLXaipDataDirectory(String profileName)
    {
        assertConfigLoaded();
        var profile = getProfile(profileName);
        if (profile == null)
        {
            return Path.of(".");
        }
        return Paths.get(profile.getLxaipDataDirectory());
    }

    /**
     * check if qualified timestamps are required
     */
    public boolean requiresQualifiedTimestamps(String profileName)
    {
        var profile = getProfile(profileName);
        return profile != null && profile.isRequireQualifiedTimestamps();
    }

    /**
     * check if a verification service URL is configured
     */
    public boolean hasVerificationService(String profileName)
    {
        var profile = getProfile(profileName);
        if (profile == null)
        {
            return false;
        }

        var validationService = profile.getValidationService();
        return validationService != null && !validationService.isEmpty();
    }

    /**
     * @return the verification service URL, may be null
     */
    public String getVerificationServiceURL(String profileName)
    {
        assertConfigLoaded();
        var profile = getProfile(profileName);
        if (profile == null)
        {
            return null;
        }
        return profile.getValidationService();
    }

    /**
     * @return the verification service URL, may be null
     */
    public URL getVerificationServiceOrNull(String profileName)
    {
        var eCardUrl = getVerificationServiceURL(profileName);
        if (eCardUrl == null)
        {
            return null;
        }
        try
        {
            return new URL(eCardUrl);
        }
        catch (MalformedURLException e)
        {
            LOG.error("Malformed URL " + eCardUrl + " passed as profile attribute 'validationService'", e);
            return null;
        }
    }

    /**
     * Get all information about a configured profile. Changes to the object will apply into the current configuration.
     */
    public ProfileType getProfile(String profileName)
    {
        return config.getProfile().stream().filter(p -> profileName.equals(p.getName())).findAny().orElse(null);
    }

    /**
     * Returns <code>true</code> if configuration has been loaded successfully by calling {@link #load(InputStream)}.
     */
    public boolean isLoaded()
    {
        return config != null;
    }

    /**
     * Asserts that the configuration has been loaded successfully.
     *
     * @throws NullPointerException iff configuration has NOT been loaded successfully
     */
    private void assertConfigLoaded()
    {
        Objects.requireNonNull(config, "Config has not been loaded successfully.");
    }

    /**
     * Returns the validator repository.
     */
    public ValidatorRepository getValidators()
    {
        return validators;
    }

    /**
     * Returns whether the verifySignatures attribute in the profile, specified by profileName, is set to true or false.
     */
    public boolean verifySignatures(String profileName)
    {
        assertConfigLoaded();
        var profile = getProfile(profileName);
        if (profile == null)
        {
            return false;
        }
        return profile.isVerifySignatures();
    }

}
