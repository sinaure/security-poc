# Oauth2

Inspired from :

https://medium.com/@bcarunmail/securing-rest-api-using-keycloak-and-spring-oauth2-6ddf3a1efcc2

## 1. deploy containers
import realms if needed (data/keycloak)

## 2. run app Startup.java

## 3. run Junit test

## 4. features:

* token retrieval 
* Programmatic creation/management of REALMS / CLIENTS / ROLES and USERS via Keycloack Admin Client
* secured API via authentication rules i.e. kc ROLES (part of the API will be free, part will be restricted to INSTANT ADMIN CLIENT, part will be restricted to NETWORK CLIENT)

## 5. TODO:
* secrets and password retrieval from Vault instead of hardcoded in config files
* per CLIENT RESOURCE based authorization 
* Identity provider for GOOGLE / FB end user login 







  