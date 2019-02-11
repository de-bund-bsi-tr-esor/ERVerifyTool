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
package de.bund.bsi.tr_esor.checktool;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Paths;
import java.util.Optional;

import javax.xml.bind.JAXBException;
import javax.xml.ws.Endpoint;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.bund.bsi.tr_esor.checktool.conf.Configurator;
import de.bund.bsi.tr_esor.checktool.conf.ProfileNames;
import de.bund.bsi.tr_esor.checktool.entry.FileParameterFinder;
import de.bund.bsi.tr_esor.checktool.entry.InputPreparator;
import de.bund.bsi.tr_esor.checktool.entry.ParameterFinder;
import de.bund.bsi.tr_esor.checktool.entry.S4VerifyOnly;
import de.bund.bsi.tr_esor.checktool.validation.ValidationScheduler;
import de.bund.bsi.tr_esor.checktool.xml.XmlHelper;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.VerificationReportType;


/**
 * Command line entry point. Call without parameters for usage.
 *
 * @author TT
 */
public final class Main
{

  private static final String CONFIG_FILE_NAME = "Config file ";

  private static final String PROFILE_NAME = "profile";

  private static final Logger LOG = LoggerFactory.getLogger(Main.class);

  static PrintStream out = System.out;

  static PrintStream err = System.err;

  private Main()
  {
    // no instances wanted
  }

  /**
   * Called from command line.
   *
   * @param args see help output for meaning
   */
  public static void main(String[] args)
  {
    Options options = getCliOptions();

    try
    {
      CommandLine cmd = new DefaultParser().parse(options, args);
      if (cmd.hasOption("conf"))
      {
        if (!loadConfig(cmd.getOptionValue("conf")))
        {
          return;
        }
        if (cmd.hasOption("server"))
        {
          runServer(cmd.getOptionValue("port", "9999"));
          return;
        }
        checkGivenProfile(cmd.getOptionValue(PROFILE_NAME));
        if (cmd.hasOption("data") || cmd.hasOption("er"))
        {
          runValidation(cmd.getOptionValue("data"),
                        cmd.getOptionValue("er"),
                        cmd.getOptionValue("out"),
                        cmd.getOptionValue(PROFILE_NAME));
          return;
        }
      }
    }
    catch (ParseException e)
    {
      err.println(e.getMessage());
      LOG.error("cannot understand parameters", e);
      return;
    }

    HelpFormatter formatter = new HelpFormatter();
    formatter.printHelp("java -jar ErVerifyTool-cli*.jar", options);
  }

  /**
   * Creates list of profiles in case of wrong input.
   */
  private static void checkGivenProfile(String profileName) throws ParseException
  {
    if (profileName != null && !Configurator.getInstance().isProfileSupported(profileName))
    {
      StringBuilder msg = new StringBuilder("Unsupported profile specified. Supported values are:");
      Configurator.getInstance().getSupportedProfileNames().forEach(n -> msg.append("\n  ").append(n));
      throw new ParseException(msg.toString());
    }
  }

  private static boolean loadConfig(String confFile)
  {
    try (InputStream ins = new FileInputStream(confFile))
    {
      Configurator.getInstance().load(ins);
      return true;
    }
    catch (IOException e)
    {
      err.println(CONFIG_FILE_NAME + confFile + " not readable: " + e.getMessage());
    }
    catch (JAXBException e)
    {
      err.println(CONFIG_FILE_NAME + confFile + " is not valid XML.\n"
                  + Optional.ofNullable(e.getMessage())
                            .orElse(Optional.ofNullable(e.getCause()).map(Throwable::getMessage).orElse("")));
    }
    catch (ReflectiveOperationException e)
    {
      err.println(CONFIG_FILE_NAME + confFile + " specifies invalid content.\n" + e.getMessage());
    }
    return false;
  }

  /**
   * Lists the supported command line parameters.
   */
  private static Options getCliOptions()
  {
    Options options = new Options();
    options.addOption("server",
                      false,
                      "start as web service (optional, ignores all other parameters except -conf and -port)");
    options.addOption("port", true, "listen port for server mode, defaults to 9999");
    options.addOption("conf", true, "path to the configuration file");
    options.addOption(PROFILE_NAME,
                      true,
                      "name of the profile to use for verification (optional, default is "
                            + ProfileNames.RFC4998 + ")");
    options.addOption("er", true, "path to the file containing the evidence record (optional)");
    options.addOption("data",
                      true,
                      "path to the file containing the secured data (optional if parameter -er is specified), "
                            + "if omitted, the ER will be validated in itself but result will be indetermined at best.");
    options.addOption("out", true, "path to the output file (optional, default is standard out)");
    options.addOption("h", false, "print this message and exit");
    return options;
  }

  /**
   * Runs ER validation as configured.
   *
   * @param data path to data file (optional if er is a CMS embedded signature)
   * @param er path to ER file (optional if data is XAIP with embedded ER(s))
   * @param destination path to output file (application uses {@link System#out} if missing)
   * @param profile name of the profile to use for verification (optional, defaults to configured value)
   */
  private static void runValidation(String data, String er, String destination, String profile)
  {
    try
    {
      ParameterFinder params = new FileParameterFinder(Optional.ofNullable(data).map(Paths::get).orElse(null),
                                                       Optional.ofNullable(er).map(Paths::get).orElse(null),
                                                       profile);
      InputPreparator prep = new InputPreparator(params);
      VerificationReportType report = ValidationScheduler.validate(prep.getValidations());
      if (destination == null)
      {
        XmlHelper.serialize(report, out);
      }
      else
      {
        try (OutputStream outs = new FileOutputStream(destination))
        {
          XmlHelper.serialize(report, outs);
        }
      }
    }

    catch (IOException | JAXBException | ReflectiveOperationException e)
    {
      err.println(e.getMessage());
      LOG.error("cannot handle input file(s)", e);
    }
  }


  /**
   * Runs the web service.
   */
  private static void runServer(String port)
  {
    String address = "http://localhost:" + port + "/ErVerifyTool/esor12/exec";
    out.println("Running S4 webservice on address " + address);
    Endpoint.publish(address, new S4VerifyOnly());
  }

}
