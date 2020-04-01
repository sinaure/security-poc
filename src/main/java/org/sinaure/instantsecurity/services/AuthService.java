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
	public TokenSet getToken(String URI, String username , String password, String client_id) throws UserUnauthorizedException;
	public TokenSet getTokenClient(String URI , String client_id, String client_credential) throws UserUnauthorizedException;
	public TokenSet refreshToken(String URI, String refresh_token, String client_id) throws UserUnauthorizedException ;
	public Keycloak getKeycloakClient( String host, String realm,String clientId, String secret);
	public Keycloak getKeycloakUser(String host, String realm, String clientId, String user, String password);
	public AccessToken decodeJWT(String host, String jwt, String realm, String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, VerificationException;

	public List<RoleRepresentation> getRoleRepresentationList(String[] defaultRoles);
	public void createRealm(Keycloak kc, RealmInstantApp realm);
	public void createClient(Keycloak kc, String realm, ClientRepresentation clientRepresentation, String[] defaultRoles);
}
