package org.sinaure.instantsecurity.services;

import com.google.gson.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.json.JSONObject;
import org.keycloak.OAuth2Constants;
import org.keycloak.RSATokenVerifier;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.*;
import org.sinaure.instantsecurity.config.SecurityContextUtils;
import org.sinaure.instantsecurity.model.RealmInstantApp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.lang.reflect.Type;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

import static java.util.Arrays.asList;

@Component
public class AuthServiceImpl implements AuthService {
    static final Logger logger = LogManager.getLogger(AuthServiceImpl.class.getName());

    @Autowired
    private RestTemplate restTemplate;

    public TokenSet getToken(String URI, String username, String password, String client_id)
            throws UserUnauthorizedException {
        logger.trace("URI: {}", URI);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<String, String>();
        requestBody.add("username", username);
        requestBody.add("password", password);
        requestBody.add("client_id", client_id);
        requestBody.add("grant_type", "password");
        logger.trace("requestBody : {}", requestBody);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        HttpEntity formEntity = new HttpEntity<MultiValueMap<String, String>>(requestBody, headers);
        try {
            ResponseEntity<String> response = restTemplate.exchange(URI, HttpMethod.POST, formEntity, String.class);
            JSONObject jsonObject = new JSONObject(response.getBody());
            String accessToken = jsonObject.getString("access_token");
            String refreshToken = jsonObject.getString("refresh_token");
            logger.info("token for user {} : {}", username, accessToken);
            return new TokenSet(accessToken, refreshToken);
        } catch (Exception e) {
            throw new UserUnauthorizedException("can't get token : Unauthorized");
        }

    }


    @Override
    public Keycloak getKeycloakClient(String host, String realm, String clientId, String secret) {
        return KeycloakBuilder.builder() //
                .serverUrl(host + "/auth") //
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS).realm(realm).clientId(clientId).clientSecret(secret)//
                .resteasyClient(new ResteasyClientBuilder().connectionPoolSize(10).build()) //
                .build();
    }


    @Override
    public AccessToken decodeJWT(String host, String jwt, String realm, String publicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, VerificationException {
        String issuer = host + "/auth/realms/" + realm;
        AccessToken accessToken = RSATokenVerifier.verifyToken(jwt, getPubKey(publicKey), issuer);
        logger.info("decodedToken : {}", SecurityContextUtils.serializeObject(accessToken));
        return accessToken;
    }

    @Override
    public boolean createUser(Keycloak kc, String realm, String clientId, UserRepresentation user) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue("test123");
        credential.setTemporary(false);
        user.setCredentials(asList(credential));
        logger.info(SecurityContextUtils.serializeObject(user));
        Response result = kc.realm(realm).users().create(user);
        if (result.getStatus() != 201) {
            logger.info("Couldn't create user. {}",result.getStatus());
            return false;
        }
        logger.info("Status: {} ", result.getStatus());
        logger.info("Users: {} ", SecurityContextUtils.serializeObject(kc.realms().realm(realm).users().list()));
        return true;
    }

    @Override
    public List<RoleRepresentation> getRoleRepresentationList(String[] roles) {
        List<RoleRepresentation> roleRepresentationList = new ArrayList<RoleRepresentation>();
        for (String r : roles
        ) {
            RoleRepresentation role = new RoleRepresentation();
            role.setId(r);
            role.setName(r);
            roleRepresentationList.add(role);
        }
        return roleRepresentationList;
    }

    @Override
    public void createRealm(Keycloak kc, RealmInstantApp realm) {
        RealmRepresentation realmRepresentation = new RealmRepresentation();
        realmRepresentation.setId(realm.getIdRealm());
        realmRepresentation.setRealm(realm.getRealm());
        realmRepresentation.setEnabled(true);
        RolesRepresentation rolesRepresentation = new RolesRepresentation();
        if (realm.getRoles() != null) {
            rolesRepresentation.setRealm(getRoleRepresentationList(realm.getRoles()));
            realmRepresentation.setRoles(rolesRepresentation);
        }
        kc.realms().create(realmRepresentation);
    }

    @Override
    public void createClient(Keycloak kc, String realm, ClientRepresentation clientRepresentation, String[] clientRoles) {
        if (clientRoles.length > 0) {
            Map<String, List<RoleRepresentation>> clientRolesRepr = new HashMap<String, List<RoleRepresentation>>();
            clientRolesRepr.put(clientRepresentation.getClientId(), getRoleRepresentationList(clientRoles));
            kc.realms().realm(realm).clients().create(clientRepresentation);
            RolesRepresentation rolesRepresentation = kc.realms().realm(realm).toRepresentation().getRoles() != null ? kc.realms().realm(realm).toRepresentation().getRoles() : new RolesRepresentation();
            rolesRepresentation.setClient(clientRolesRepr);
            RealmRepresentation realmRepr = kc.realms().realm(realm).toRepresentation();
            realmRepr.setRoles(rolesRepresentation);
            realmRepr.setDefaultRoles(Arrays.asList(clientRoles));
            kc.realms().realm(realm).update(realmRepr);
        }
    }

    @Override
    public String getSecretByClientId(String clientId) {
        //make a call to KV store (vault)
        //TODO
        return "d686dc95-c1b9-4758-9036-e433e3ecb860";
    }

    private static PublicKey getPubKey(String publicK)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] publicBytes = Base64.decode(publicK);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    @Override
    public Keycloak getKeycloakUser(String host, String realm, String clientId, String user, String password) {
        return KeycloakBuilder.builder() //
                .serverUrl(host + "/auth") //
                .grantType(OAuth2Constants.PASSWORD).realm(realm).clientId(clientId).username(user).password(password)//
                .resteasyClient(new ResteasyClientBuilder().connectionPoolSize(10).build()) //
                .build();
    }


    @Override
    public TokenSet refreshToken(String URI, String refresh_token, String client_id) throws UserUnauthorizedException {
        logger.trace("URI: {}", URI);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<String, String>();
        requestBody.add("refresh_token", refresh_token);
        requestBody.add("client_id", client_id);
        requestBody.add("grant_type", "refresh_token");
        logger.trace("requestBody : {}", requestBody);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        HttpEntity formEntity = new HttpEntity<MultiValueMap<String, String>>(requestBody, headers);
        try {
            ResponseEntity<String> response = restTemplate.exchange(URI, HttpMethod.GET, formEntity, String.class);
            JSONObject jsonObject = new JSONObject(response.getBody());
            String access_token = jsonObject.getString("access_token");
            String r_token = jsonObject.getString("refresh_token");
            TokenSet set = new TokenSet(access_token, r_token);
            logger.info("token for  : {}", access_token);
            return set;
        } catch (Exception e) {
            throw new UserUnauthorizedException("can't get token : Unauthorized");
        }
    }

    @Override
    public TokenSet getTokenClient(String URI, String client_id, String client_credential)
            throws UserUnauthorizedException {
        logger.trace("URI: {}", URI);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<String, String>();
        requestBody.add("client_secret", client_credential);
        requestBody.add("client_id", client_id);
        requestBody.add("grant_type", "client_credentials");
        logger.trace("requestBody : {}", requestBody);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        HttpEntity formEntity = new HttpEntity<MultiValueMap<String, String>>(requestBody, headers);
        try {
            ResponseEntity<String> response = restTemplate.exchange(URI, HttpMethod.POST, formEntity, String.class);
            JSONObject jsonObject = new JSONObject(response.getBody());
            String accessToken = jsonObject.getString("access_token");
            String refreshToken = jsonObject.getString("refresh_token");
            logger.info("token for clientId {} : {}", client_id, accessToken);
            return new TokenSet(accessToken, refreshToken);
        } catch (Exception e) {
            throw new UserUnauthorizedException("can't get token : Unauthorized");
        }

    }


}
