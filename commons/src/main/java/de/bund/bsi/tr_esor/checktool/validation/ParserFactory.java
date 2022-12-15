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

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool._1.ParserType;
import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.parser.ASN1EvidenceRecordParser;
import de.bund.bsi.tr_esor.checktool.parser.BinaryParser;
import de.bund.bsi.tr_esor.checktool.parser.CmsSignatureParser;
import de.bund.bsi.tr_esor.checktool.parser.EvidenceRecordTypeParser;
import de.bund.bsi.tr_esor.checktool.parser.Parser;
import de.bund.bsi.tr_esor.checktool.parser.UnsupportedXaipParser;
import de.bund.bsi.tr_esor.checktool.parser.XaipParser;
import de.bund.bsi.tr_esor.checktool.xml.LXaipReader;


/**
 * Factory for parsers.
 *
 * @author TT
 */
public final class ParserFactory
{

  private static final Logger LOG = LoggerFactory.getLogger(ParserFactory.class);

  private static final ParserFactory INSTANCE = new ParserFactory();

  private static final String ALL_PROFILE_KEY = "all";

  private final Map<String, List<Supplier<Parser<?>>>> parsersByProfile = new HashMap<>();

  private final List<Class<Parser<?>>> configured = new ArrayList<>();

  private final Map<String, List<Class<Parser<?>>>> configuredByProfile = new HashMap<>();


  private ParserFactory()
  {
    var parserForAllProfiles = new ArrayList<Supplier<Parser<?>>>();
    parserForAllProfiles.add(UnsupportedXaipParser::new);
    parserForAllProfiles.add(EvidenceRecordTypeParser::new);
    parserForAllProfiles.add(ASN1EvidenceRecordParser::new);
    parserForAllProfiles.add(CmsSignatureParser::new);
    parserForAllProfiles.add(BinaryParser::new); // Make sure this is the last one!
    parsersByProfile.put(ALL_PROFILE_KEY, parserForAllProfiles);
    var conf = Configurator.getInstance();
    for ( var name : conf.getSupportedProfileNames() )
    {
      var lXaipReader = new LXaipReader(Configurator.getInstance().getLXaipDataDirectory(name));
      parsersByProfile.put(name, List.of(() -> new XaipParser(lXaipReader)));
      configuredByProfile.put(name, loadClasses(conf.getParsers(name)));
    }
    configured.addAll(loadClasses(conf.getParsers()));
  }

  /**
   * Singleton getter.
   */
  public static ParserFactory getInstance()
  {
    return INSTANCE;
  }

  /**
   * Parses given input by trying all parsers of the specified profile and returns the result of the first
   * parser which can parse the input.
   */
  public static Object parse(InputStream ins, String profileName) throws IOException
  {
    for ( var parser : ParserFactory.getInstance().getAvailableParsers(profileName) )
    {
      parser.setInput(ins);
      if (parser.canParse())
      {
        return parser.parse();
      }
    }
    return null; // unreachable: each content is at least application/octet-stream
  }

  @SuppressWarnings("unchecked")
  private List<Class<Parser<?>>> loadClasses(List<ParserType> parsers)
  {
    List<Class<Parser<?>>> result = new ArrayList<>();
    for ( var parser : parsers )
    {
      try
      {
        result.add((Class<Parser<?>>)Class.forName(parser.getClassName()));
      }
      catch (ClassNotFoundException e)
      {
        LOG.error("ignoring configured class " + parser.getClassName(), e);
      }
    }
    return result;
  }


  /**
   * Returns all configured parsers which are available for a given profile name and all predefined parsers.
   * Parsers which have been configured come first.
   */
  public Iterable<Parser<?>> getAvailableParsers(String profileName)
  {
    List<Supplier<Parser<?>>> internal = new ArrayList<>();
    if (parsersByProfile.containsKey(profileName))
    {
      internal.addAll(parsersByProfile.get(profileName));
    }
    else
    {
      internal.addAll(parsersByProfile.get(Configurator.getInstance().getDefaultProfileName()));
    }
    internal.addAll(parsersByProfile.get(ALL_PROFILE_KEY));
    List<Class<Parser<?>>> fromConf = new ArrayList<>();
    Optional.ofNullable(configuredByProfile.get(profileName)).ifPresent(fromConf::addAll);
    fromConf.addAll(configured);
    return () -> new Parsers(internal, fromConf);
  }


  private static class Parsers implements Iterator<Parser<?>>
  {

    private final List<Supplier<Parser<?>>> internal;

    private final List<Class<Parser<?>>> configured;

    Parsers(List<Supplier<Parser<?>>> internal, List<Class<Parser<?>>> configured)
    {
      this.internal = internal;
      this.configured = configured;
    }

    @Override
    public boolean hasNext()
    {
      return !(internal.isEmpty() && configured.isEmpty());
    }

    @Override
    public Parser<?> next()
    {
      if (!configured.isEmpty())
      {
        try
        {
          return configured.remove(0).getDeclaredConstructor().newInstance();
        }
        catch (InstantiationException | IllegalAccessException | NoSuchMethodException
          | InvocationTargetException e)
        {
          throw new IllegalStateException(e);
        }
      }
      if (!internal.isEmpty())
      {
        return internal.remove(0).get();
      }
      throw new NoSuchElementException();
    }

  }

  // In case of too many implemented parsers, rewrite the factory to filter the parsers for requested types.

}
