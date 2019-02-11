ER Verify Tool - Web Application Archive
========================================

**Version: ${version}**

The web application archive (_WAR_) of the ER Verify Tool is used to provide a
web service for verification of evidence records when deployed in an Apache
Tomcat server.

See the product documentation section Installation/Webservice in Tomcat for
detailed information.

In short:

- Install Apache Tomcat 7, make sure  variables `\$JAVA_HOME`, `\$CATALINA_HOME`
  and `\$CATALINA_BASE` have been set correctly.
- To use multiple instances with different configurations of the ER-Verify tool within the same server, a valid configuration inside the war under `WEB-Inf/classes` may be provided.
  If no configuration is packed within the .war file, the application searches in the `conf` folder of the Tomcat for a configuration named `ErVerifyTool.xml`.
- Create a valid Log4J2 configuration XML file named `log4j2.xml` in the `conf`
  folder of Tomcat.
- Copy the file `ErVerifyTool.war` to the `webapps`folder of Tomcat.
- Restart Tomcat and find the application under the URL
  `http://<host>:<port>/ErVerifyTool/`.


Files
-----

The WAR consists of the following files:

- `ErVerifyTool.war` : web application archive to be deployed in a Tomcat
- `README.md`        : this file
