#!/bin/bash

echo
echo "【adapt waf install start】"
echo

PWD_PATH=$(cd -P $(dirname $0) && pwd)

read -p "Please Input OpenResty Directory, /usr/local is Default " OPENRESTY_DIR

sudo mkdir -p ${OPENRESTY_DIR}/logs
sudo mkdir -p ${OPENRESTY_DIR}/adapt-waf

sudo sed -i "s#{op-dir}#${OPENRESTY_DIR}#g" ${OPENRESTY_DIR}/adapt-waf/nginx.conf

sudo /bin/cp -rpf ${PWD_PATH}/* ${OPENRESTY_DIR}/adapt-waf/
sudo /bin/cp -rpf ${OPENRESTY_DIR}/adapt-waf/script/conf/* ${OPENRESTY_DIR}/nginx/conf/

echo
echo "【adapt waf install success】"
echo
echo
echo "【adapt waf start: ${OPENRESTY_DIR}/nginx/sbin/nginx -c ${OPENRESTY_DIR}/nginx/conf/nginx.conf】"
echo