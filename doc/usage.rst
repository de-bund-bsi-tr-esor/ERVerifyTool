Usage
=====

Configuration
-------------

The configuration is contained in an XML file, which can be edited with any
text editor. The schema for creating configuration files can be found in the
config directory.

Edit the enclosed file ``config/config.xml`` to match your requirements. The
following properties can be specified in the ``General``-section:

* ``VerifierID`` (mandatory) The ID of the verifier to appear in the
  verification report. Choose any URI which describes your installation and
  configuration of the ErVerifyTool.
* ``DefaultProfileName`` (mandatory) URI to define the profile that will be
  used by the command line calls or by web service calls which do not
  explicitly specify another profile. Allowed values are any profiles you
  specify in the following section and the built-in profiles
* ``https://tools.ietf.org/html/rfc4998``
* ``http://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/``
      ``TechnischeRichtlinien/TR03125/BSI_TR_03125_Anlage_ERS_V1_2.html``
      ``#Basis-ERS-Profil`` (line breaks do not belong to the value)

The following settings are needed only in case you want to add a plug-in
(Validator, Parser or HashCreator) or want to use some application part other
than the default.

* ``General/ConfiguredObjects`` (optional) Here you may specify plug-ins which
  are applicable in all supported profiles. These settings may be replaced by
  special definitions in a ``Profile``-section.
* ``Profile`` (optional) This part may occur several times to define new
  profiles and objects which replace the defaults for the respective profile. A
  profile must contain the name-attribute (URI).

Within the ``Profile`` and ``General/ConfiguredObjects`` sections you may
specify a validator which handles a certain type of parsed object. Any
configured validator replaces the respective default validator which is built
into the application itself. Settings for the profile overwrite general
settings.

A ``Validator`` element is defined with the following values:

* ``className`` (mandatory) - the fully qualified name of the validator class
* ``param`` (optional, may occur several times) - name and value of a
  constructor parameter. Parameter type must be String.
* ``targetType`` (mandatory) - fully qualified class name of objects that the
  validator can handle. If two validators are defined in the same section, one
  targeting a specific target type and the other some base class, the
  application will chose the one for the most specific type which matches the
  object to be validated. Both validator class and target class must be present
  in the class path. Target types occurring in the current version of
  ErVerifyTool without additions (see "Appendix: Internal data types" for more
  details) are:

  * ``org.bouncycastle.tsp.TimeStampToken``
  * ``de.bund.bsi.tr_esor.checktool.data.AlgorithmUsage``
  * ``de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStamp``
  * ``de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampChain``
  * ``de.bund.bsi.tr_esor.checktool.data.ArchiveTimeStampSequence``
  * ``de.bund.bsi.tr_esor.checktool.data.EvidenceRecord``

In the ``General`` section you may additionally specify a hash creator. Default
is local hashing, you might want to use some certified crypto module instead.
Furthermore, that section allows you to define name space prefixes for XML
serialization by adding ``NamespacePrefix`` elements. This may be necessary
because web service access might disregard the prefixes used in a given XAIP.
Define an empty prefix to use as the target (prefix-less) name space. Default
name space prefixes are as defined in TR-ESOR XAIP V1.2 schema.

The current configuration schema allows defining additional parsers. However,
because the application already contains all necessary parsers for the
currently supported use cases, you do not have to specify any further parsers.

Adding a validator :
  Add the library containing your validator to the application class path. Add
  a ``Validator`` element to the appropriate part of the configuration.

Removing a validator :
  Remove the respective ``Validator`` element from the configuration.

Listing the configured validators :
  Read the configuration file.

Checking the correctness of the configuration file :
  This is done automatically when you start the application. In case of
  problems, the application will terminate immediately and write an appropriate
  message to standard output.


General Validation
------------------

Validating evidence records can be done via command line application or via web
service. In both cases, the evidence record may be given separately, within a
XAIP or within a CMS signature. Evidence records within a XAIP or CMS structure
are only recognized if they are embedded correctly as specified in TR-ESOR 1.2
or CAdES, respectively.

If an evidence record is given but no protected data is passed to the
application, only the internal structure of the evidence record will be
validated. If no evidence record is embedded within the given XAIP and no
evidence record is given separately, an empty verification report is returned.

Profiles supported by the application are:

* ``https://tools.ietf.org/html/rfc4998``
* ``http://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/``
  ``TechnischeRichtlinien/TR03125/BSI_TR_03125_Anlage_ERS_V1_2.html``
  ``#Basis-ERS-Profil`` (line breaks do not belong to the value)
* Any further profiles specified by administrator in the configuration.


Calling the Command Line Application
------------------------------------

With parameter ``-h`` or in case of invalid parameters, the application just
displays a help message:

.. code-block:: none

   usage: java -jar ErVerifyTool-cli*.jar
    -conf <arg>      path to the configuration file
    -data <arg>      path to the file containing the secured data (optional
                     if parameter -er is specified), if omitted, the ER will
                     be validated in itself but result will be indetermined
                     at best.
    -er <arg>        path to the file containing the evidence record
                     (optional)
    -out <arg>       path to the output file (optional, default is standard
                     out)
    -port <arg>      listen port for server mode, defaults to 9999
    -profile <arg>   name of the profile to use for verification (optional,
                     default is https://tools.ietf.org/html/rfc4998)
    -server          start as web service (optional, ignores all other
                     parameters except -conf and -port)

If the ``data`` parameter is a file containing a XAIP, then the evidence
records embedded in that XAIP are checked as well. All other formats given as
``data`` parameter are handled as binary protected content and are not
interpreted in any way.

The file given as parameter ``er`` may contain:

* an ASN.1 evidence record
* an XML with root tag {http://www.bsi.bund.de/tr-esor/xaip/1.2}:evidenceRecord
  containing an ASN.1 evidence record   In this case the application will fail
  if the data parameter does not contain an XAIP with specified AOID and
  version.
* a CMS signature with embedded evidence records (CAdES-E-ERS)

To verify evidence records, typically call:

``checktool -conf <FILE> -data <XAIP or bin file> [-er <detached evidence
record>]``

The output of the validation will be a verification report with all checked
details.

To start the stand-alone web service, call:

``checktool -conf <FILE> -server -port <PORT>``

By default, the command line application will create a log file named
erVerifyTool.log in the working directory. To change logging behavior, set the
system variable ``log4j.configuration`` to point to your custom Log4J2
configuration.
See https://logging.apache.org/log4j/2.x/manual/configuration.html#XML for
further details.

Calling the web service
-----------------------

The service WSDL is identical to the one defined in TR-ESOR version 1.2. Only
the ArchiveVerifyRequest is supported here. The web service requires no
authentication and can be invoked by any appropriate web service client.

The service WSDL can be reached at the following URL:

``http://<HOST>:<PORT>/ErVerifyTool/esor12/exec?wsdl``

If the application is deployed on Apache Tomcat as a war file, additional
information is displayed at

``http://<HOST>:<PORT>/ErVerifyTool``

Inside the verify request, the data to check must be provided under the
following XPaths.

+--------------------------+--------------------------------------------------+
| **Element**              | **XPath**                                        |
+==========================+==================================================+
| detached evidence record | /VerifyRequest/SignatureObject/Base64Signature or|
|                          | /VerifyRequest/SignatureObject/Other/            |
|                          | evidenceRecord/asn1EvidenceRecord                |
+--------------------------+--------------------------------------------------+
| binary protected data    | /VerifyRequest/InputDocuments/Document/Base64Data|
| elements                 |                                                  |
+--------------------------+--------------------------------------------------+
| XAIP which may contain   | /VerifyRequest/InputDocuments/Document/InlineXML/|
| embedded evidence records| XAIP                                             |
+--------------------------+--------------------------------------------------+
| CMS signature with       | /VerifyRequest/SignatureObject/Base64Signature   |
| embedded evidence records|                                                  |
+--------------------------+--------------------------------------------------+

When validating a detached evidence record or a detached CMS signature with
embedded evidence records, you should specify all protected data elements or
the addressed XAIP, respectively, as input document(s). Otherwise, the tool
checks only the internal structure of the evidence record itself.

If an evidence record or a CMS signature is given as value of ``/VerifyRequest/
SignatureObject/Base64Signature``, then the application will detect the type of
the given object by analyzing the value itself.

Furthermore, the request usually should contain an optional input of type

``{urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:schema#}``
``ReturnVerificationReport``

to cause the application to return a verification report. Without that optional
input the response will only contain a result with technical information
whether the request was processed, but not the result of the validation. In
most cases you should set the value of attribute ``ReportDetailLevel`` to

``urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:reportdetail:
allDetails``.

Other allowed values are:

* ``urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:reportdetail:
  noDetails``
* ``urn:oasis:names:tc:dss-x:1.0:profiles:verificationreport:reportdetail:
  noPathDetails`` (line breaks are not part of the values)

If the validation of the evidence record should be done using another profile
than the default profile specified in the configuration, the attribute
``profile`` of the ``VerifyRequest`` must be set. The optional input
``VerifyUnderSignaturePolicy`` is currently not supported.
