#!/bin/bash

export TOMCAT_VERSION=$1
export TOMCAT_URL=$2

if ! [ -x "$(command -v wget)" ]
then
  curl -O -s $TOMCAT_URL/$TOMCAT_VERSION.tar.gz
else
  wget -nv "$TOMCAT_URL/$TOMCAT_VERSION.tar.gz"
fi

tar xf $TOMCAT_VERSION.tar.gz
cp ErVerifyTool.war $TOMCAT_VERSION/webapps/
cp conf/ErVerifyTool.xml $TOMCAT_VERSION/conf/
chmod +x $TOMCAT_VERSION/bin/catalina.sh
export CATALINA_HOME=$(pwd)/$TOMCAT_VERSION
export CATALINA_BASE=$(pwd)/$TOMCAT_VERSION
$TOMCAT_VERSION/bin/catalina.sh run
