@setlocal EnableDelayedExpansion
@echo off
chcp 1252 > NUL

rem do-single.bat dir-name, e.g. do-single.bat fhg-101-1-lxaip_v1_v2-er_v1_att

if ___%1___==______ goto NO_PARAM_SET

call env.cmd
set ER_TT_BIN=%ERT_HOME%\cli\bin
set ER_CFG_DIR=%__CONFIG_DIR__%
set ER_EXEC=checktool.bat

set TEST_MODULE_NAME=ERVT-V1.3.3-Single

set TEST_HOME=%~dp0
set _DD_=%date:~0,2%
set _MM_=%date:~3,2%
set _YY_=%date:~8,2%
set _YYYY_=%date:~6,4%

if NOT EXIST %TEST_HOME%\%1 goto DIR_NOT_EXIST

set TMP01=%1
set TST_ID=%TMP01:~0,7%

del %TEST_HOME%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-result.csv > NUL 2>&1
echo Origin;p/n;Directory;Kind;Profile;Result;Description;Remarks >> %TEST_HOME%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-result.csv

set RESULT_OVERVIEW_FILE=%TEST_HOME%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-result-overview.txt
del %RESULT_OVERVIEW_FILE% > NUL 2>&1

echo ^|¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯^| >> %RESULT_OVERVIEW_FILE%
echo ^| Overview of the result of the test executed at %_YYYY_%.%_MM_%.%_DD_%                ^| >> %RESULT_OVERVIEW_FILE%
echo ^|___________________________________________________________________________^| >> %RESULT_OVERVIEW_FILE%
echo. >> %RESULT_OVERVIEW_FILE%

set __WER__=FHG

cd %ER_TT_BIN%

set TEST_DIR=%TEST_HOME%\%1
set TEST_DIR_NAME=%1
call %TEST_HOME%\%1\!TST_ID!-tf-setup.bat
call %TEST_HOME%\do-work.cmd

cd %TEST_HOME%
call validate_xpath.cmd %1

goto THE_END

:DIR_NOT_EXIST
echo [E] specified directory %TEST_HOME%\%1 does not exist
goto THE_END

:NO_PARAM_SET
echo [E] Please provide the test directory name.
goto THE_END


:THE_END
@endlocal