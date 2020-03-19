ER Verify Tool
==============

**Version: 1.0.7**

The _ER Verify Tool_ is used to check the conformity of an evidence record to
requirements of TR-ESOR-ERS in the version of 1.2.1.

More information about the _ER Verify Tool_ can be found in the product
documentation, which can be generated as a part of the building process. 
(Start reading with `doc/pdf/ErVerifyTool.pdf`)

Please note that all `README.md` files in this distribution are plain text
files in markdown syntax. You can read these files with any text viewer or use
a markdown viewer, for instance a
[Firefox plugin](https://addons.mozilla.org/en-US/firefox/addon/markdown-viewer-webext/)
for nicer formatting.

License
-----
This software is underlying the rules of the following license: 
[Apache License Version 2.0, January 2004](http://www.apache.org/licenses/LICENSE-2.0.txt)

Files
-----

The ER Verify Tool consists of the following files:

- `cli`       : directory containing the command line interface of ER Verify
                Tool
- `war`       : directory with web application archive of ER Verify Tool
- `config`    : directory with example configuration and schema
- `doc`       : directory with the product documentation
- `sdk`       : directory with libraries for implementing extensions and Java
                clients
- `LICENSE`   : text file with license description
- `README.md` : this file

Prerequisites
-----
Following software packages are necessary in order to build the binaries and documentation from sources: 

- openjdk-8-jdk (the tool has been tested with this version of java),
- gradle,
- python (at leat version 2.7.*), 
- python-pip, 
- git,
- latex, 
- python-sphinx, 
- latexmk, 
- javasphinx,

How to build the ERVerifyTool on Ubuntu 18.04 LTS
-----
Install software (if not already existing)

- `sudo apt-get install python python-pip git openjdk-8-jdk python-sphinx latexmk gradle`
- `sudo apt-get install texlive texlive-binaries texlive-extra-utils texlive-fonts-extra texlive-fonts-recommended texlive-publishers texlive-font-utils texlive-latex-extra texlive-latex-recommended`
- `sudo pip install javasphinx`

Get the sources of ErVerifyTool from the github (e.g. in ~/working)

- `git clone https://github.com/ervta/ERVerifyTool.git`

Optional check and set up the java version

- required is java 1.8, as installed above, thus check with java -version, if the correct one is setup as default
- in case a newer java verion as 1.8 (e.g. in case of Ubuntu 18.04.4 it is a java 11), it has to be changed e.g. by using `update-alternatives`.

Setup gradle wrapper (optional, if you are about to use the gradle wrapper)

- `cd ~/working/ERVerifyTool`
- `gradle -version`
- setup the gradle version in ~/working/ERVerifyTool/gradle/wrapper/gradle-wrapper.properties (e.g. on if gradle version is 3.4.1, than the property distributionUrl should be set to `https\://services.gradle.org/distributions/gradle-3.4.1-bin.zip`)
- Test it with `sh gradlew -version`

Build the binaries

- `cd ~/working/ERVerifyTool`
- in case the wrapper should be used: `sh gradlew clean build -Prelease -DskipIntegrationTests --continue` (in order to perform integration tests a special infrastructure is needed, which is not a part of the open source package)
- or only with gradle `gradle clean build -Prelease -DskipIntegrationTests --continue`

Build the documentation

- `cd ~/working/ERVerifyTool/doc`
- `python doc.py` 

How to install and use the ErVerifyTool
----

After successfull built of the ErVerifyTool, the distribution file can be found under `ERVerifyTool/all/build/dists/`. 
In order to install the tool and do some first tests, please follow those steps:

1. Copy the distribution package into your test directory, e.g.: `cp ~/src/ERVerifyTool/all/build/dists/ErVerifyTool-all-1.0.7-bin.zip ~/apps/`
2. change to test directory: `cd ~/apps`
3. unzip the binaries: `unzip ErVerifyTool-all-1.0.7-bin.zip`
4. copy the configuration into distribution. `cp ~/src/ERVerifyTool/config/config-rfc4998-offline.xml ~/apps/ErVerifyTool-all-1.0.7/config/`
5. run: `~/apps/ErVerifyTool-all-1.0.7/cli/bin/checktool -conf ~/apps/ErVerifyTool-all-1.0.7/config/config-rfc4998-offline.xml -data ~/src/ERVerifyTool/test/1.RFC4998-bin-data_er/BIN.bin -er ~/src/ERVerifyTool/test/1.RFC4998-bin-data_er/BIN_ER.ers`- which will produce an output on the console or `~/apps/ErVerifyTool-all-1.0.7/cli/bin/checktool -conf ~/apps/ErVerifyTool-all-1.0.7/config/config-rfc4998-offline.xml -data ~/src/ERVerifyTool/test/1.RFC4998-bin-data_er/BIN.bin -er ~/src/ERVerifyTool/test/1.RFC4998-bin-data_er/BIN_ER.ers -out /tmp/1.RFC4998-bin-data_er-VR.xml` - will store the output under `/tmp/1.RFC4998-bin-data_er-VR.xml`, which is a verfification report in XML.
6. run: `~/apps/ErVerifyTool-all-1.0.7/cli/bin/checktool -conf ~/apps/ErVerifyTool-all-1.0.7/config/config-rfc4998-offline.xml -data ~/src/ERVerifyTool/test/2.RFC4998-XAIP-ER/XAIP_OK_V1_V2_ER1.xml`- will produce output on the console

  

Known Issues
----

* [**KI-001**] - a XAIP containing two versions (V1 and V2) and an ebmedded evidence record belonging to version V1; element `xaip:evidenceRecord` points to the wrong version (to V2 instead of to V1); uncaught exception on the console -> no reports is returned.
* [**KI-002**] - a XAIP containing two versions (V1 and V2) and an ebmedded evidence record belonging to version V1; the element `xaip:relatedObjects` is pointing to an not existing version; the minor code of the result states a hash value mismatch, which is not quite accuratly.
* [**KI-003**] - a XAIP containing two versions (V1 and V2) and an ebmedded evidence record belonging to version V1; wrong AOID in the element `xaip:evidenceRecord`; `majorReult` contains *valid* intead of expected *indetermind* in case of online check.
* [**KI-004**] - output on the console doesn't produce the closing `LF`
