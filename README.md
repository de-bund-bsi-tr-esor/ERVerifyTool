# ER Verify Tool

The _ER Verify Tool_ is used to check the conformity of an evidence record against requirements
of TR-ESOR-ERS in version 1.3.

The former version of _ER Verify Tool_, which is working with the version 1.2.1 of TR-ESOR-ERS, can be obtained from branch _V1.2.2_ in this repository.

More information about the _ER Verify Tool_ can be found in the product documentation (cf. `doc/ErVerifyTool.pdf`).

## License

This software is underlying the rules of the following license:
[Apache License Version 2.0, January 2004](http://www.apache.org/licenses/LICENSE-2.0.txt)

The software was created by Governikus GmbH & Co. KG on behalf of the Federal Office for Information Security.

## Prerequisites

To run the application at least the following is required:

- Java 11 (e.g. OpenJDK)
- Tomcat 10 for Application Server Web Service mode

The gradle build system does not need to be installed.
Instead, all gradle build commands can be executed using the gradle wrapper (gradlew), which is located in
the main folder of the source code distribution.

## Project Structure

The project is structured as follows:

- `cli`       : directory containing the command line interface of ER Verify Tool
- `war`       : directory with web application archive of ER Verify Tool
- `config`    : directory with example configuration and configuration schema
- `doc`       : directory with the product documentation
- `sdk`       : directory with libraries for implementing extensions and Java clients

## Contact

Federal Office for Information Security (BSI)<br>
Godesberger Allee 185-189<br>
53175 Bonn, Germany<br>
phone: +49 228 99 9582-0<br>
fax: +49 228 99 9582-5400<br>
e-mail: bsi@bsi.bund.de<br>
and<br>
Governikus GmbH & Co. KG<br>
Hochschulring 4<br>
28359 Bremen<br>
e-mail: helpline@governikus.de

# Build instructions

Install a version of the Java 11 development kit.

For Ubuntu 20.04 LTS e.g.:

```
sudo apt-get install openjdk-11-jdk
```

Make sure Java 11 is installed correctly:
Either the `java` command is available on the PATH or the `JAVA_HOME` environment variable is set up accordingly.

Build the artifact with

```
./gradlew clean build -Prelease -DskipIntegrationTests
```

You may replace `./gradlew` with an installed version of `gradle` of the same version (see URL in
gradle/wrapper/gradle-wrapper.properties).

In order to perform all integration tests online timestamp validation must be configured correctly (cf. product
documentation)

```
./gradlew integrationTest
```

# Run CLI

The *ER Verify Tool* provides a CLI. For webserver mode and WAR deployment see the product documentation.

The zip artifact is located at `all/build/dists/`. Unzip the build artifact and change into the `cli/bin` directory.

Running `./checktool` without any arguments will provide you with a help message

```
cli/bin$ ./checktool
```

To use the default `config.xml` run the CLI as follows

```
cli/bin$ ./checktool -conf ../../config/config.xml -data some-xaip.xml -er some-er.er
```

This will print the XML *VerificationReport* to standard out.

See the product documentation for more options and possible configurations.

# Known Issues

* [**KI-001**] - handling of the CAdES with embedded evidence record (CAdES-E-ERS) according to ETSI TS 119 122-3 in the special case, CAdES doesn't contain any unsigned attributes. While creating the corresponding evidence record, **(1)** the CAdES can be hashed as-is, meaning without the unsigned attributes structure, or **(2)** an empty unsigned attributes structure can be created before the hash value has been computed. The same strategy had to be applied in case of verification, but there is no standardised possibility to store the strategy information in the CAdES and ETSI TS 119 122-3 doesn't specify, which approach shall be chosen, which means, the both approaches have to be tried. The ERVT does support currently only the **(2)** strategy version. The strategy **(1)** will supported in the next version of ERVT.