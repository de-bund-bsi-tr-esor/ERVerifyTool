
rem --- begin of the customer configuration section  ---
set JAVA_HOME=c:\apps\Java64\jdk-11.0.15+10

set _PYTHON_HOME_=c:\Users\tku\AppData\Local\Programs\Python\Python310\

set ERVT_HOME_DIR=c:\Projects\BSI\ErTestTool\65.Build\230327\ERVerifyTool

rem set YES, if remote verification service is available, or NO otherwise
set ONLINE_ENABLED=NO

rem --- end of the customer configuration section  ---


set JRE_HOME=%JAVA_HOME%\jre

set ERT_HOME=%ERVT_HOME_DIR%\all\build\install\

set __CONFIG_DIR__=%ERVT_HOME_DIR%/test-env/__CONFIG__

set CHECKTOOL_OPTS=-Dlog4j.configurationFile=%ERT_HOME%/config/log4j2.xml

set PATH=%PATH%;%_PYTHON_HOME_%