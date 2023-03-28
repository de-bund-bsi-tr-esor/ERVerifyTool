@setlocal EnableDelayedExpansion
@echo off

cls
chcp 1252 > NUL

call env.cmd
set ER_TT_BIN=%ERT_HOME%\cli\bin
set ER_CFG_DIR=%__CONFIG_DIR__%
set ER_EXEC=checktool.bat

set DO_ALL_TESTS=true

set TEST_MODULE_NAME=ERVT-V1.3.3

set TEST_HOME=%~dp0
set _DD_=%date:~0,2%
set _MM_=%date:~3,2%
set _YY_=%date:~8,2%
set _YYYY_=%date:~6,4%

del %TEST_HOME%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-result.csv > NUL 2>&1
echo Origin;p/n;Directory;Kind;Profile;Result;Description;Remarks >> %TEST_HOME%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-result.csv

set RESULT_OVERVIEW_FILE=%TEST_HOME%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-result-overview.txt
del %RESULT_OVERVIEW_FILE% > NUL 2>&1
echo Overview of the results of the tests executed at %_YYYY_%.%_MM_%.%_DD_% >> %RESULT_OVERVIEW_FILE%


:start_choice
echo 1. RFC4998 - Governikus
echo 2. Basis-ERS-Profile - Governikus
echo 3. RFC4998 - OpenLimit
echo 4. RFC4998 - BearingPoint
echo 5. RFC4998 - FOKUS
echo 9. Perform all tests
echo 0. Cancel processing
echo.
set /p choice=Choose on of the options: 
IF NOT '%choice%'=='' set choice=%choice:~0,1%
if '%choice%'=='1' (
	set DO_ALL_TESTS=false
	goto RFC4998_GOV
)
if '%choice%'=='2' (
	set DO_ALL_TESTS=false
	goto BASIS_GOV
)
if '%choice%'=='3' (
	set DO_ALL_TESTS=false
	goto RFC4998_OL
)
if '%choice%'=='4' (
	set DO_ALL_TESTS=false
	goto RFC4998_BE
)
if '%choice%'=='5' (
	set DO_ALL_TESTS=false
	goto RFC4998_FOKUS
)
if '%choice%'=='9' (
	set DO_ALL_TESTS=true
	goto :START_TESTS
)
if '%choice%'=='0' (
	set DO_ALL_TESTS=false
	goto CANCELED
)
echo %choice% is not a valid option, try again
echo.
goto start_choice

:START_TESTS

:RFC4998_GOV
echo [i] calling TS-Tests-V08-rfc4998-Gov.cmd ...
call TS-Tests-rfc4998-Gov.cmd
IF NOT '%DO_ALL_TESTS%'=='true' GOTO END_TESTS

:BASIS_GOV
echo [i] calling TS-Tests-V08-Basis-ERS-Profile-Gov.cmd ...
call TS-Tests-Basis-ERS-Profile-Gov.cmd
IF NOT '%DO_ALL_TESTS%'=='true' GOTO END_TESTS

:RFC4998_OL
echo [i] calling TS-Tests-V08-rfc4998-OL.cmd ...
call TS-Tests-rfc4998-OL.cmd
IF NOT '%DO_ALL_TESTS%'=='true' GOTO END_TESTS

:RFC4998_BE
echo [i] calling TS-Tests-V08-BE.cmd ...
call TS-Tests-BE.cmd
IF NOT '%DO_ALL_TESTS%'=='true' GOTO END_TESTS

:RFC4998_FOKUS
echo [i] calling TS-Tests-V08-rfc4998-FHG.cmd ...
call TS-Tests-rfc4998-FHG.cmd
IF NOT '%DO_ALL_TESTS%'=='true' GOTO END_TESTS

goto END_TESTS

:CANCELED
echo [i] Processing has ben canceled!
goto END_TESTS

:END_TESTS

endlocal