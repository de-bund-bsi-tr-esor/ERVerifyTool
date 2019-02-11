Installation
============

Preconditions
-------------

The ErVerifyTool is a pure Java application and should be able to run under any
Java virtual machine. It has been tested on the following operating systems:

* Windows 10
* Windows 7
* Ubuntu Linux 16.4 or higher
* Suse Linux 12.3
* Fedora Linux 25

Make sure Java(TM) SE Runtime Environment Version 1.8.0 in the most recent
update is installed on your system. Furthermore, set the ``JAVA_HOME``
environment variable to point to your Java installation.

Do not include any out-dated additional libraries into your Java installation.
Especially, make sure no application installed a BouncyCastle of version 1.54
or older into the directory ``$JAVA_HOME/jre/lib/ext``. Having an out-dated
BouncyCastle in your class path may cause the application to fail.

For installation and configuration, you will need a text editor and a program
to unpack a ZIP archive.

To create an extension of the program, in addition to the preconditions above
you will need the following:

* Gradle 4.4.1 or higher
* Java(TM) SDK 1.8.0 or higher
* an appropriate IDE, for instance Eclipse

Command Line Application
------------------------

After unpacking the distribution ZIP file, the command line application does
not need any further installation. It is started by calling the script
``checktool`` (for Linux) or ``checktool.cmd`` (for Windows), respectively, in
the directory ``cli/bin``.

In case of Linux, you may want to make the script executable by calling ``chmod
u+x checktool``.

Before using the application, you have to create a valid configuration. See the
following chapter for further details.

Standalone Web Service
----------------------

Install the command line application. To start the service, configure the
application and call ``checktool.sh -server -port <PORT> -conf <FILE>`` where
``<PORT>`` is the number of the port to listen on and ``<FILE>`` is the name of
the configuration file. With Windows, call ``checktool.cmd`` with same
parameters. Be aware that you need root or administrator privileges,
respectively, in case the port is less than 1000.

Web Service in Tomcat
---------------------

Install Apache Tomcat version 7.0.73 or higher. Set the environment variables
``CATALINA_HOME`` and ``CATALINA_BASE`` to point to the installation directory
of Tomcat. In case of manual installation in Linux, do not forget to make the
scripts executable by calling ``chmod u+x $CATALINA_HOME/bin/*.sh``. Copy the
file ``war/ErVerifyTool.war`` into the directory ``$CATALINA_HOME/webapps``.

Create a configuration of the ErVerifyTool application as described in the
following chapter. Copy that file into the directory ``$CATALINA_HOME/conf``
and name it ``ErVerifyTool.xml``. Furthermore, create a valid Log4J2
configuration ``log4j2.xml`` in the same directory.

In case you want to run multiple instances of the ErVerifyTool, with different configurations
within the same server, you may pack a valid configuration inside the .war file.
Place a configuration file named ``ErVerifyTool.xml`` inside the .war file under ``WEB-Inf/classes``.
If no configuration is packed within the .war file, the application searches
in the ``$CATALINA_HOME/conf`` folder of the Tomcat for a configuration named ``ErVerifyTool.xml``.

Restart Tomcat. The web application is reachable on a local machine with
default Tomcat port at:

``http://localhost:8080/ErVerifyTool/``

That overview page provides a link to the TR-ESOR S.4 web service as well as
information about the loaded configuration.
