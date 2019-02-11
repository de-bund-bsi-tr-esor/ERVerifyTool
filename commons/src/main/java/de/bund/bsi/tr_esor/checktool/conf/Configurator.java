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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
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


/**
 * Reads the configuration file and provides values in named methods.
 * <p>
 * Before using methods to get configuration values the method {@link #load(InputStream)} has to be called
 * successfully.
 *
 * @author TT
 */
public final class Configurator
{

  private static final Logger LOG = LoggerFactory.getLogger(Configurator.class);

  private static final Configurator INSTANCE = new Configurator();

  private Configuration config;

  private ValidatorRepository validators;

  private Configurator()
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
   *
   * @param ins
   * @throws JAXBException
   * @throws ReflectiveOperationException
   */
  public void load(InputStream ins) throws JAXBException, ReflectiveOperationException
  {
    try
    {
      JAXBContext ctx = JAXBContext.newInstance(ObjectFactory.class.getPackage().getName());
      Unmarshaller u = ctx.createUnmarshaller();
      SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
      setSchemaForUnmarshaller(u, schemaFactory);
      Object x = u.unmarshal(ins);
      config = (Configuration)x;
      validators = new ValidatorRepository();
      if (config.getGeneral().getConfiguredObjects() != null)
      {
        addToRepo(config.getGeneral().getConfiguredObjects(), null);
      }
      for ( ProfileType profile : config.getProfile() )
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

  private void addToRepo(ConfiguredObjectsCollection collection, String profileName)
    throws ReflectiveOperationException
  {
    for ( ValidatorType val : collection.getValidator() )
    {
      Class<?> validatorClass = Class.forName(val.getClassName().trim());
      Class<?> targetClass = Class.forName(val.getTargetType().trim());
      TypeAnalyzer genTypes = assertIsValidatorForTarget(validatorClass, targetClass);
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
    Map<String, String> params = cnf.getParameter()
                                    .stream()
                                    .collect(Collectors.toMap(ParameterType::getName,
                                                              ParameterType::getValue));
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
      return clazz.newInstance();
    }
  }

  private void assertConstructorPresent(Class<?> validatorClass, boolean paramsEmpty)
    throws ReflectiveOperationException
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
        LOG.debug("Validator class does not have a constructor with empty parameter, assuming it takes a map",
                  e);
      }
    }
    try
    {
      validatorClass.getConstructor(Map.class);
    }
    catch (NoSuchMethodException e)
    {
      throw new ReflectiveOperationException("Missing constructor with Map parameter in class: "
                                             + validatorClass.getName(), e);
    }
  }

  private static TypeAnalyzer assertIsValidatorForTarget(Class<?> clazz, Class<?> targetClass)
    throws ReflectiveOperationException
  {
    if (!Validator.class.isAssignableFrom(clazz))
    {
      throw new ReflectiveOperationException("Configured class does not extend Validator: "
                                             + clazz.getName());
    }
    TypeAnalyzer genTypes = new TypeAnalyzer(clazz);
    if (genTypes.getFirstMatchingTypeArgument(targetClass) == null)
    {
      throw new ReflectiveOperationException("Validator " + clazz.getName()
                                             + " does not comply with target class: "
                                             + targetClass.getName());
    }
    return genTypes;
  }

  /**
   * Returns <code>true</code> if profile is configured.
   *
   * @param profileName
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
   * Returns a list of supported profiles.
   */
  public List<String> getSupportedProfileNames()
  {
    assertConfigLoaded();
    List<String> result = config.getProfile().stream().map(ProfileType::getName).collect(Collectors.toList());
    // avoid dependency:
    result.addAll(ProfileNames.getPredefinedProfileNames());
    return result;
  }

  /**
   * Returns the parser configurations for specified profile.
   *
   * @param name
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
   *
   * @param name
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
   * Returns <code>true</code> if configuration has been loaded successfully by calling
   * {@link #load(InputStream)}.
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
    Objects.requireNonNull(config, "Config has not been loaded succuessfully.");
  }

  /**
   * Returns the validator repository.
   */
  public ValidatorRepository getValidators()
  {
    return validators;
  }

}
