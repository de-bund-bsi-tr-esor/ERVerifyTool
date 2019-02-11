ER Verify Tool - Command Line Interface
=======================================

**Version: ${version}**


The command line interface (_CLI_) is used to verify evidence records in two
ways:

1. Run the CLI to verify files directly.
2. Start the CLI as a web service which listens for verify requests.

See also the product documentation.


Files
-----

The CLI consists of the following files:

- `checktool.cmd` : Executable to run the CLI on Windows.
- `checktool.sh`  : Executable to run the CLI on Linux.
- `lib`           : Directory which contains all JARs needed by the CLI.
- `README.md`     : This file.


Requirements
------------

- Java 1.8.0
- Environment variable `\$JAVA_HOME` has been set correctly.


Installation
------------

No special installation is required. Just copy the files to an appropriate
directory.


Usage
-----

The CLI needs a configuration XML file. Details about the content of this file
can be found in the product documentation.

To show usage information call:

    checktool -h

To verify evidence records call:

    checktool -conf <file> [-profile <profile name>] -data <XAIP or bin file> \
    [-er <detached evidence record>]

To start the stand-alone web service call:

    checktool -conf <file> -server -port <port>
