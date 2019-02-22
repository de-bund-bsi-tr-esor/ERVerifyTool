ER Verify Tool - Configuration
==============================

**Version: 1.0.7**

Here you find templates for configuration files for the _ER Verify Tool_ and
for its logging, configuration schema  as well as two examples of the configuration in order to check the evidence record compliance with *RFC4998* or *Basis-ER-Profile,* comming from TR-ESOR-ERS.

See product documentation section "Configuration" on how to fill in these data.

Upon creating your configuration, you can check its vaditiy by calling the
command line interface with `-conf` parameter set only.

You can actually use two modes for checking the evidence record:
1. **offline** - only the syntax and the hash value of the root of the hash tree will be checked 
2. **online** - additionally an online verification service will be used and the signature of the timestamp will be checked

==Hint! The second mode ist not supported out of the box, because of a verification service is necessary for that. ==

Files
-----

- `config.xml` : template for the applications configuration file
- `Config.xsd` : XML schema for configuration file
- `log4j2.xml`  : example configuration for logging
- `README.md`  : this file
- `config-rfc4998-offline.xml` : example of configuration for checking (offline) evidence records against *RFC4998*
- `config-BasisERProfile-offline.xml` : example of configuration for checking (offline) evidence records against *Basis-ER-Profile*
