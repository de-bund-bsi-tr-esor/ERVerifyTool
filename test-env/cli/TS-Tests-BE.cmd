@setlocal ENABLEDELAYEDEXPANSION
@echo off
chcp 1252 > NUL

set __WER__=BE

cd %ER_TT_BIN%

echo BE Tests according to RFC4998/Basis-ER-Profil, additional test incl. some negative tests ...

for /f %%a in ('dir /B/S /AD %TEST_HOME%\bep-0*') do (
  set TEST_DIR=%%a
  set TEST_DIR_NAME=%%~na
  set TST_ID=!TEST_DIR_NAME:~0,7!
  call %%a\!TST_ID!-tf-setup.bat
  call %TEST_HOME%\do-work.cmd                                 
)

@echo --- BE Tests according to RFC4998/Basis-ER-Profil - DONE ---

@endlocal