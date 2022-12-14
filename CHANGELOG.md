# Changelog

## v1.3.3

**Changes:**

- The handling of namespaces included in a XAIP structure has been reworked.
- Line endings are now preserved during the canonicalization of XAIP contents for hash value checks.

**Enhancements:**

- XAIPs can now be included as Base64XML in web service requests.

**Closed Issues:**

- When using non-exclusive canonicalization, XML namespaces are not added to XML elements prior to canonicalization anymore.


## v1.3.2 (2022-10-26)

**Changes:**

- The Basis-ERS profile has been adjusted according to the TR-ESOR 1.3 documentation.

## v1.3.1 (2022-10-12)

**Closed Issues:**

- An issue leading to a test failure in the build process has been resolved.

## v1.3.0 (2022-09-30)

**Changes:**
- The tool is now based on the TR-ESOR 1.3 documents and schemas.
- The validation of XAIPs conforming to the TR-ESOR 1.2-Schema is no longer possible.
- The profile to check Evidence Records according to TR-ESOR Appendix ERS has been renamed to Basis-ERS.
- The connection URL for an online validation service (eCard) now needs to be configured as an attribute of the selected profile in the configuration XML.

**Enhancements:**
- Checking inline and detached signatures in a XAIP is now supported. For comprehensive check results an online validation service is required.
- The tool now detects if a XAIP according to TR-ESOR 1.1 or TR-ESOR 1.2 schema is provided and produces an appropriate error message.
- Binary contents can now been extracted from the XAIP container and dumped into a folder.
- Document-related timestamps can now be checked in the same way as signatures.
- Signed MetaData elements can now be checked.
- Profiles can now be configured to only accept qualified timestamps (an eCard service producing a SignatureQualityType according to ETSI SVR is required).
- MetaData and Credential elements can now be resolved from a DataObjectReference according to LXAIP specification.
- Information on the qualification status of timestamp certificates can now be extracted from a SignatureQualityType according to ETSI SVR. The information is embedded into the ChainingOK report inside the DetailedCertificatePathValidity. 


## v1.2.0 (2022-08-23)

**Changes:**

- The eCard timestamp validation is now eIDAS compliant. If available, the source value of the timestamped hash is passed on validation.

## v1.1.2 (2022-02-10)

**Enhancements:**

- There is a new mode for checking sorted and unsorted hash concatenations. It is named "both" and will accept both 
  modes (sorted/unsorted) as valid.
- A new check for the CMS version of CMS-encoded timestamps has been added.

**Changes:**

- The supported Tomcat version is now Tomcat 10 (tested using 10.0.16)
- The usage of Java Enterprise dependencies has been migrated to Jakarta Enterprise
- The gradle build now uses Gradle 7.3.3
- Building the software should now always use the gradle wrapper (gradlew)
- The automated tests for the war-project can now only be run in Linux environments
- The hashSorted property hash been renamed to hashMode. The possible values are now named "unsorted" (default), 
  "sorted" and "both".
- More detailed information on problems while using LXAIPs are now included in the report.

**Closed Issues:**

- The software does not expect the all protected data to be present in case a bin is checked against an Evidence Record
  containing multiple protected elements anymore.
- An error that leads to content data not being checked when the webservice is deployed in a Tomcat container has been
  resolved.

## v1.1.1 (2021-07-08)

**Enhancements:**

- The documentation has been updated for Ubuntu 20.04
- A new check for excess hash values has been implemented. Excess hash values in evidence records checked against
  XAIP contents will now be reported as invalid with minor code HashValueMismatch.

**Changes:**

- The documentation creation via python was removed and replaced with a .odt and a .pdf file.

**Closed Issues:**

- The software does not crash anymore when an evidence record is referencing an unknown XAIP version.
  Instead, a report stating the error result is generated.

## v1.1.0 (2021-01-14)

**Features:**

- Support for logical XAIPs (LXAIP) added. In order to check the conformity on an LXAIP the DataObjectReference (URI)
  of the data object must refer to a file that can be resolved relative to the new `lxaipDataDirectory` configuration parameter.

  E.g. if the LXAIP's protected data is located at `/home/user/lxaip/data.bin` the referring parameter `lxaipDataDirectory` 
  should be configured to `/home/user/lxaip` and the DataObjectReference should have the URI parameter set to `URI="data.bin"`.

**Enhancements:**

- Upgrade to Java 11
- Upgrade to Tomcat 9

**Closed Issues:**

- Timestamp validation variant added where hashes are sorted binary ascending according to [\#2](https://github.com/de-bund-bsi-tr-esor/ERVerifyTool/issues/2).
  The sorted hash variant can be configured using the `hashSorted` property.

## v1.0.8 (2020-11-05)

**Bug Fixes:**

- Fix gradle task `publishLocal`
