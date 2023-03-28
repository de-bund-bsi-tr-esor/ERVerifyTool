@setlocal ENABLEDELAYEDEXPANSION
@echo off
chcp 1252 > NUL

set __WER__=Gov

cd %ER_TT_BIN%

echo --- Governikus according to BASIS-ERS-Profile ---

for /f %%a in ('dir /B /S /AD %TEST_HOME%\gov-3*') do (
  set TEST_DIR=%%a
  set TEST_DIR_NAME=%%~na
  set TST_ID=!TEST_DIR_NAME:~0,7!
  call %%a\!TST_ID!-tf-setup.bat
  call %TEST_HOME%\do-work.cmd                                 
)

@echo --- Governikus according to BASIS-ERS-Profile - DONE ---

@endlocal