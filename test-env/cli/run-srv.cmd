@setlocal
@echo off
chcp 1252 > NUL

call env.cmd

set ER_TT_BIN=%ERT_HOME%\cli\bin
set ER_CFG_DIR=%ERT_HOME%\config

%ER_TT_BIN%\checktool.bat -conf %ER_CFG_DIR%\config-RFC4998-online.xml -server -port 9999

endlocal
