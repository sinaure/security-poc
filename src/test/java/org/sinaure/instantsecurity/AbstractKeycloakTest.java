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
	protected static String pubKeyInstant = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhSX3F2Zw0eOFAPa/5+aMi1Rc0teUZpMsG4ftLLAISNrz8iV4Rpqqk/summIp3EOuB0uoY3GT3UCxBOfk4r4p6ZLBcz+6fqirX1K8Ei7s/PldozJW/Gi2729WNl+Cp878Hgu6v3GcjQR7NquBfaMssS5o64CHNRZYE5Al/sfAIVL32EDwe5kdMdkVb4LfXTPmHH4ougjCmp0Dy6BxH0kNkvRsg8m8KNtDnRSwvBakw1DaKe5Y/4lheIUdHB4MZBvqo4+fEQj1ZO9QRk2Kb1U5oYPzmtGRcKzeVcGswfx3gCSeab6pgXCOMUkjV9muvNJ3Q8tZjFG8eiOfOKrguONGlQIDAQAB";
	protected static String client_instant = "instant";
	protected static String realm_instant = "instant";
	protected static String[] instantRoles = {"app_editor","superadmin","uma_protection"};

	
	protected static String client_instant_secret = "1bbf4c87-812c-4171-a9fa-16ade8380045";
	protected static String baseURL = root + "/";
	protected static String redirectUri = root + "/*";
	protected static String webOrigins = root;

//	#APP LEVEL

	protected static String pubKey1 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhSX3F2Zw0eOFAPa/5+aMi1Rc0teUZpMsG4ftLLAISNrz8iV4Rpqqk/summIp3EOuB0uoY3GT3UCxBOfk4r4p6ZLBcz+6fqirX1K8Ei7s/PldozJW/Gi2729WNl+Cp878Hgu6v3GcjQR7NquBfaMssS5o64CHNRZYE5Al/sfAIVL32EDwe5kdMdkVb4LfXTPmHH4ougjCmp0Dy6BxH0kNkvRsg8m8KNtDnRSwvBakw1DaKe5Y/4lheIUdHB4MZBvqo4+fEQj1ZO9QRk2Kb1U5oYPzmtGRcKzeVcGswfx3gCSeab6pgXCOMUkjV9muvNJ3Q8tZjFG8eiOfOKrguONGlQIDAQAB";
	protected static String realm_1 = "lime";
	protected static String client_id_1 = "lime";
	protected static String client_secret_1 = "6c64f5f7-8479-4558-9afb-20b5e6482f39";
	protected static String pubKey2 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhSX3F2Zw0eOFAPa/5+aMi1Rc0teUZpMsG4ftLLAISNrz8iV4Rpqqk/summIp3EOuB0uoY3GT3UCxBOfk4r4p6ZLBcz+6fqirX1K8Ei7s/PldozJW/Gi2729WNl+Cp878Hgu6v3GcjQR7NquBfaMssS5o64CHNRZYE5Al/sfAIVL32EDwe5kdMdkVb4LfXTPmHH4ougjCmp0Dy6BxH0kNkvRsg8m8KNtDnRSwvBakw1DaKe5Y/4lheIUdHB4MZBvqo4+fEQj1ZO9QRk2Kb1U5oYPzmtGRcKzeVcGswfx3gCSeab6pgXCOMUkjV9muvNJ3Q8tZjFG8eiOfOKrguONGlQIDAQAB";
	protected static String realm_2 = "lime";
	protected static String client_id_2 = "zou";
	protected static String client_secret_2 = "8f697911-edee-4f28-a7f9-e88382e68c14";

	protected String getUriApp(String client_id) {
		return root + "/api/client/" + client_id + "/users";
	}
}
