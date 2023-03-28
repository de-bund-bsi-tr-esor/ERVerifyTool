echo [i] %TEST_DIR_NAME%: %CLABEL%

set IHASH_MODE=
if NOT \\\%HASH_MODE%\\\ == \\\\\\ (
  echo [i] using specified hash-mode: %HASH_MODE%
  set IHASH_MODE=-%HASH_MODE%
)

echo [i] hash mode used: !IHASH_MODE!
echo [i] preparing the given AOID for using as output dir name
echo [i] input AOID: %AOID%
set AOID=!AOID:-=_!
echo [i] output AOID after transformation: %AOID%

set ONL_OUT_DIR=%TEST_DIR%\%_YYYY_%-%_MM_%-%_DD_%-online-output
set OFL_OUT_DIR=%TEST_DIR%\%_YYYY_%-%_MM_%-%_DD_%-offline-output

if EXIST %ONL_OUT_DIR%\%AOID% (
	echo [i] Deleting the old online result dir: %ONL_OUT_DIR%\%AOID%
	rmdir %ONL_OUT_DIR%\%AOID% /s /q > NUL
)

if EXIST %OFL_OUT_DIR%\%AOID% (
	echo [i] Deleting the old offline result dir: %OFL_OUT_DIR%\%AOID%
	rmdir %OFL_OUT_DIR%\%AOID% /s /q > NUL
)

if \\\%CDATA%\\\ == \\\\\\ (
  echo [i] No "data" parameter specified.
  if %ONLINE_ENABLED% == YES (
    echo [i] online verification of sigs and tsps is enabled!
    echo %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-online%IHASH_MODE%.xml -er %TEST_DIR%\%CER% -out %ONL_OUT_DIR% > %TEST_DIR%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-command.txt
    call %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-online%IHASH_MODE%.xml -er %TEST_DIR%\%CER% -out %ONL_OUT_DIR%
  )
  echo %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-offline%IHASH_MODE%.xml -er %TEST_DIR%\%CER% -out %OFL_OUT_DIR% >> %TEST_DIR%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-command.txt
  call %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-offline%IHASH_MODE%.xml -er %TEST_DIR%\%CER% -out %OFL_OUT_DIR%
  rem check.py test-name online-result online-exp offline-result off-exp
  goto check_results
)

if \\\%CER%\\\ == \\\\\\ (
  echo [i] No "er" parameter specified.
  if %ONLINE_ENABLED% == YES (
    echo [i] online verification of sigs and tsps is enabled!
    echo %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-online%IHASH_MODE%.xml -data %TEST_DIR%\%CDATA% -out %ONL_OUT_DIR% > %TEST_DIR%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-command.txt
    call %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-online%IHASH_MODE%.xml -data %TEST_DIR%\%CDATA% -out %ONL_OUT_DIR%
  )
  echo %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-offline%IHASH_MODE%.xml -data %TEST_DIR%\%CDATA% -out %OFL_OUT_DIR% >> %TEST_DIR%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-command.txt
  call %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-offline%IHASH_MODE%.xml -data %TEST_DIR%\%CDATA% -out %OFL_OUT_DIR%
  goto check_results
)

echo [i] The "data" and "er" parameters have been specified. 
if %ONLINE_ENABLED% == YES ( 
  echo [i] online verification of sigs and tsps is enabled!
  echo %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-online%IHASH_MODE%.xml -data %TEST_DIR%\%CDATA% -er %TEST_DIR%\%CER% -out %ONL_OUT_DIR% > %TEST_DIR%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-command.txt
  call %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-online%IHASH_MODE%.xml -data %TEST_DIR%\%CDATA% -er %TEST_DIR%\%CER% -out %ONL_OUT_DIR%
)
echo %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-offline%IHASH_MODE%.xml -data %TEST_DIR%\%CDATA% -er %TEST_DIR%\%CER% -out %OFL_OUT_DIR% >> %TEST_DIR%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-command.txt
call %ER_EXEC% -conf %ER_CFG_DIR%\config-%CPROF%-offline%IHASH_MODE%.xml -data %TEST_DIR%\%CDATA% -er %TEST_DIR%\%CER% -out %OFL_OUT_DIR%

:check_results

echo [i] Renaming the verification reports ...

if EXIST %ONL_OUT_DIR%\%AOID%\report.xml (
	echo [i] Renaming %ONL_OUT_DIR%\%AOID%\report.xml into %TST_ID%-ONL-report.xml
	ren %ONL_OUT_DIR%\%AOID%\report.xml %TST_ID%-ONL-report.xml
)

if EXIST %OFL_OUT_DIR%\%AOID%\report.xml (
	echo [i] Renaming %OFL_OUT_DIR%\%AOID%\report.xml into %TST_ID%-OFF-report.xml
	ren %OFL_OUT_DIR%\%AOID%\report.xml %TST_ID%-OFF-report.xml
)

echo [i] Verification of the results...
%TEST_HOME%\check.py %TEST_DIR_NAME% "%CLABEL%" %TEST_DIR%\%_YYYY_%-%_MM_%-%_DD_%-online-output\%AOID%\%TST_ID%-ONL-report.xml %TEST_DIR%\%TST_ID%-tf-exp-onl.txt %TEST_DIR%\%_YYYY_%-%_MM_%-%_DD_%-offline-output\%AOID%\%TST_ID%-OFF-report.xml %TEST_DIR%\%TST_ID%-tf-exp-off.txt %__WER__% %CPROF% %RESULT_OVERVIEW_FILE% %ONLINE_ENABLED% >> %TEST_HOME%\%_YYYY_%-%_MM_%-%_DD_%-%TEST_MODULE_NAME%-result.csv

:end
