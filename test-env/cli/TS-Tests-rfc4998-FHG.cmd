@setlocal ENABLEDELAYEDEXPANSION
@echo off
chcp 1252 > NUL

set __WER__=FOKUS

cd %ER_TT_BIN%

echo [i] --- Fraunhofer FOKUS according to RFC4998 ---

for /f %%a in ('dir /B/S /AD %TEST_HOME%\fhg-1*') do (
  set TEST_DIR=%%a
  set TEST_DIR_NAME=%%~na
  set TST_ID=!TEST_DIR_NAME:~0,7!
  call %%a\!TST_ID!-tf-setup.bat
  call %TEST_HOME%\do-work.cmd                                 
)

echo [i] -- Fraunhofer FOKUS according to RFC4998 - DONE ---

endlocal