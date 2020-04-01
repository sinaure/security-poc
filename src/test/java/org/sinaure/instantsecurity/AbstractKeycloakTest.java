package org.sinaure.instantsecurity;

public abstract class AbstractKeycloakTest {
	protected static String root = "http://localhost:8085";
	protected static String keycloakhost = "http://localhost:8081";
	// TEST
	protected static String new_realm = "newRealm";
	protected static String new_client = "newClient";
	protected static String new_realm_key = "";
	protected static String new_client_secret = "EDITOR";
	// MASTER
	protected static String master_realm = "master";
	protected static String master_client_id = "admin-cli";
	protected static String master_admin = "keycloak";
	protected static String master_password = "9vJaTwrJnKS6";

	// INSTANT CLI --> access to REST API
	protected static String pubKeyInstant = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlvSModu0JW/8lYTtg0Lo+c69WkcCmNipXUAJXae0czaqnpnLP8dufbt4LRNPdrJ4xcPzQ+qZKE2vwJpolYbfXdSKfBDRq/mwrCObX5qFqLAr4zvDBKIQnF4qlMZhigdxEdXD979xk7Q+kh3rG+G1jhf1wKvah9y7UkHeUyoSYyY64QQdi/ACXEho/S/zh85QN8vt8UshSuQZSLZP6HO/zUcWYVoZH/7kFxXPM/MX6Tc2cLPt6OiHvmEel1LXOBEB8JTJ2WwL+U5VRZrztNUT0pZc+D+b8rHucYHqzHFO5n5teuopntJtD3OH+pR3Bn3rBHFU6V8TxjIh8NnXTaax9QIDAQAB";
	protected static String client_instant = "instant";
	protected static String realm_instant = "instant";
	protected static String[] instantRoles = {"SUPERADMIN"};

	
	protected static String client_instant_secret = "1bbf4c87-812c-4171-a9fa-16ade8380045";
	protected static String baseURL = root + "/";
	protected static String redirectUri = root + "/*";
	protected static String webOrigins = root;

//	#APP LEVEL
    protected static String[] appRoles = {"USER","uma_authorization"};
	protected static String pubKey1 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh1OC3oB00hbDLUfL5/0mkYwAs3A2WuQMtmkegHnYGumrr8CE/Mwcg9XzdQpuPhlLpWWl1v48PvvHCZIsUwUseMRXvDabEXh5sPYdr7bwLDZUVZJ+qsc08SWYGzrhwlD/HSxknWJJKEK6Mi6BfQRYpsS/XmX2o11ixvWlDd7qUHP/8fsEWW1ZSH2R5RcbRzFL7mthW3aCTG09reyZq4YjZUz9k5xugHyZ1w5RzxHkDGlKbtfEEysWt8myqccGbiYqh0bHclX0Yt5mHcooEu3/EFN0+aL09rOOKJcfj/L+3Yr1hr2FVNGL0ej7YUCBTs7XjZks12+mr/svTYpLmnii7QIDAQAB";
	protected static String realm_1 = "lime";
	protected static String client_id_1 = "lime";
	protected static String client_secret_1 = "00c66dbd-42d7-4e16-bae5-1211deee0f81";
	protected static String pubKey2 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh1OC3oB00hbDLUfL5/0mkYwAs3A2WuQMtmkegHnYGumrr8CE/Mwcg9XzdQpuPhlLpWWl1v48PvvHCZIsUwUseMRXvDabEXh5sPYdr7bwLDZUVZJ+qsc08SWYGzrhwlD/HSxknWJJKEK6Mi6BfQRYpsS/XmX2o11ixvWlDd7qUHP/8fsEWW1ZSH2R5RcbRzFL7mthW3aCTG09reyZq4YjZUz9k5xugHyZ1w5RzxHkDGlKbtfEEysWt8myqccGbiYqh0bHclX0Yt5mHcooEu3/EFN0+aL09rOOKJcfj/L+3Yr1hr2FVNGL0ej7YUCBTs7XjZks12+mr/svTYpLmnii7QIDAQAB";
	protected static String realm_2 = "zou";
	protected static String client_id_2 = "zou";
	protected static String client_secret_2 = "8f697911-edee-4f28-a7f9-e88382e68c14";

	protected String getUriApp(String client_id) {
		return root + "/api/client/" + client_id + "/users";
	}
}
