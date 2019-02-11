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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TimeZone;
import java.util.stream.Collectors;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Wrapper class for all supported crypto algorithms.
 *
 * @author BVO
 */
public final class AlgorithmCatalog
{

  private static final Logger LOG = LoggerFactory.getLogger(AlgorithmCatalog.class);

  private static final AlgorithmCatalog INSTANCE = new AlgorithmCatalog();

  private final Map<String, SupportedHashAlgorithm> supportedAlgorithms = new HashMap<>();

  private static final String ISO_8601_24H_FULL_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";

  /**
   * Parses the algorithms.json from the resources folder and initializes the AlgorithmCatalog instance.
   *
   * @throws IOException
   * @throws ScriptException
   * @throws ParseException
   */
  @SuppressWarnings("unchecked")
  private AlgorithmCatalog()
  {
    SimpleDateFormat dateParser = new SimpleDateFormat(ISO_8601_24H_FULL_FORMAT);
    dateParser.setTimeZone(TimeZone.getDefault());
    try
    {
      for ( Entry<String, Object> catalogEntry : jsonToMap().entrySet() )
      {
        Map<String, Object> values = (Map<String, Object>)catalogEntry.getValue();
        Map<String, String> parameters = null;
        Date validity = dateParser.parse(values.get("validity").toString());
        if (values.containsKey("parameter"))
        {
          parameters = (Map<String, String>)values.get("parameter");
        }
        List<Map<String, String>> oids = (List<Map<String, String>>)values.get("oids");
        List<String> usedOids = oids.stream().map(om -> om.get("oid")).collect(Collectors.toList());
        supportedAlgorithms.put(catalogEntry.getKey(),
                                new SupportedHashAlgorithm(validity, parameters, usedOids));
      }
    }
    catch (ScriptException | IOException | ParseException e)
    {
      LOG.error("algorithms.json is not parseable", e);
    }

  }

  /**
   * Returns the current instance of the AlgorithmCatalog.
   */
  public static AlgorithmCatalog getInstance()
  {
    return INSTANCE;
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> jsonToMap() throws ScriptException, IOException
  {
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                                                                          this.getClass()
                                                                              .getResourceAsStream("/algorithms.json"),
                                                                          StandardCharsets.UTF_8)))
    {
      String fileContent = reader.lines().collect(Collectors.joining("\n"));
      String script = "Java.asJSONCompatible(" + fileContent + ")";
      return (Map<String, Object>)engine.eval(script);
    }
  }


  /**
   * Returns supported algorithms.
   */
  public Map<String, SupportedHashAlgorithm> getSupportedAlgorithms()
  {
    return supportedAlgorithms;
  }

  /**
   * Representation of a hash algorithm.
   */
  public static class SupportedHashAlgorithm
  {

    private final Date validity;

    private final Map<String, String> parameter;

    private final List<String> oids;

    /**
     * Constructs the Hash Algorithm Representation.
     *
     * @param validity Date until algorithm is valid.
     * @param parameter creation parameter
     * @param oids list of OIDs
     */
    SupportedHashAlgorithm(Date validity, Map<String, String> parameter, List<String> oids)
    {
      this.validity = validity;
      this.parameter = parameter;
      this.oids = oids;
    }

    /**
     * Returns the validity date.
     */
    public Date getValidity()
    {
      return (Date)validity.clone();
    }

    /**
     * Returns the creation parameter.
     */
    public Map<String, String> getParameter()
    {
      return parameter == null ? Collections.emptyMap() : parameter;
    }

    /**
     * Returns the list of oids.
     */
    public List<String> getOids()
    {
      return oids;
    }

  }

}
