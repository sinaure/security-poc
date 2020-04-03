package org.sinaure.instantsecurity.services;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.*;
import org.sinaure.instantsecurity.model.RealmInstantApp;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface AuthService {
	TokenSet getToken(String URI, String username , String password, String client_id) throws UserUnauthorizedException;
	TokenSet getTokenClient(String URI , String client_id, String client_credential) throws UserUnauthorizedException;
	TokenSet refreshToken(String URI, String refresh_token, String client_id) throws UserUnauthorizedException ;
	Keycloak getKeycloakClient( String host, String realm,String clientId, String secret);
	Keycloak getKeycloakUser(String host, String realm, String clientId, String user, String password);
	AccessToken decodeJWT(String host, String jwt, String realm, String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, VerificationException;
	boolean createUser(Keycloak kc, String realm, String clientId,  UserRepresentation userRepresentation);

	List<RoleRepresentation> getRoleRepresentationList(String[] defaultRoles);
	void createRealm(Keycloak kc, RealmInstantApp realm);
	void createClient(Keycloak kc, String realm, ClientRepresentation clientRepresentation, String[] defaultRoles);
	String getSecretByClientId(String clientId);
}
