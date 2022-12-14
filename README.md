# ER Verify Tool

The _ER Verify Tool_ is used to check the conformity of an evidence record against requirements 
of TR-ESOR-ERS in version 1.3.

More information about the _ER Verify Tool_ can be found in the product documentation (cf. `doc/ErVerifyTool.pdf`).

## License

This software is underlying the rules of the following license:
[Apache License Version 2.0, January 2004](http://www.apache.org/licenses/LICENSE-2.0.txt)

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

You may replace `./gradlew` with an installed version of `gradle` of the same version (see URL in gradle/wrapper/gradle-wrapper.properties).

In order to perform all integration tests online timestamp validation must be configured correctly (cf. product documentation)

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
