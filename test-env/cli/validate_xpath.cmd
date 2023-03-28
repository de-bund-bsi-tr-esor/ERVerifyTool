@setlocal EnableDelayedExpansion
@echo off
chcp 1252 > NUL

if ___%1___==______ goto NO_PARAM_SET

set TEST_HOME=%~dp0

if NOT EXIST %TEST_HOME%\%1 goto DIR_NOT_EXIST

call env.cmd
set _DD_=%date:~0,2%

if NOT ___%2___==______ (
  set _DD_=%2
)  

set _MM_=%date:~3,2%
set _YY_=%date:~8,2%
set _YYYY_=%date:~6,4%

set TMP01=%1
set TST_ID=%TMP01:~0,7%

call %TEST_HOME%\%1\!TST_ID!-tf-setup.bat

set AOID=!AOID:-=_!

validate_xpath.py %1 !TST_ID! !AOID! !_YYYY_!-!_MM_!-!_DD_! !ONLINE_ENABLED!

goto THE_END

:DIR_NOT_EXIST
echo [E] specified directory %TEST_HOME%\%1 does not exist
goto THE_END

:NO_PARAM_SET
echo [E] Please provide the test directory name.
goto THE_END

:THE_END

endlocal