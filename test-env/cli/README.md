# Test environment for cli

This directory does contain a set of test cases implemented for usage with the command line interpreter (cli) version of _Er Verify Tool_.

Notice! Please consider, the execution scripts have been provided only for Windows.

## Prerequisites

In order to run the scripts at least following is required:

- Java Runtime Environment (JRE) version 11 or later
- Python 3

## Setup instructions

If you want to execute the test cases by using the __provided scripts__, you have to set up the environemtn first. In order to do it, please edit the file _env.cmd_ and set the following environment variabels:

- _JAVA_HOME_ - pointer to your JRE-installation,
- _\_PYTHON_HOME\__ - pointer the the python executable,
- _ERVT_HOME_DIR_ - pointer to the home directory of this project
- _ONLINE_ENABLED_ - set to "YES" indicates the online verification of the signatures and time stamps will also be performed, otherwise (set to "NO") only local verification (cryptographically correctness) will be performed.

## Usage

- _do-all.cmd_ - perform all tests, or chosen part of them (a menu will be displayed and the scope to be covered can be selected)
 - _do-single.cmd \<dir-name\>_ - perform only test case, specified by the dir-name parameter
 - _validate_xpath.cmd \<dir-name> [day]_ - try to validate the assertions, if the results of the verification exists. the results are stored always with the date of execution day, thus it is necesseary to have the test case exceted at the same day, or to specify the day as a second call parameter, in order the corresponding results could be find (e.g. the test has been performed on 12-th mai 2023 and the validation ist about to be performed at 14-th mai, than the command should be: _validate_xpath.cmd <dir-name> 12_)
