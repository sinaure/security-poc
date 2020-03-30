#!/bin/bash

PASSWORD=$(date +%s|sha256sum|base64|head -c 32)
echo $PASSWORD
vault write kv/keycloak keycloak=$PASSWORD lease=1800s lease_max=3600s 
#UPDATE also in keycloak 