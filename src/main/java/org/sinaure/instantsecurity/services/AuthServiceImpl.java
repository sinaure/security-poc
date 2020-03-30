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
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Component
public class AuthServiceImpl implements AuthService {
	static final Logger logger = LogManager.getLogger(AuthServiceImpl.class.getName());
	private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SS'Z'");
	public static Gson gson = new GsonBuilder().registerTypeAdapter(LocalDateTime.class, new JsonSerializer<LocalDateTime>() {
		public JsonElement serialize(LocalDateTime src, Type typeOfSrc, JsonSerializationContext context) {
			return new JsonPrimitive(formatter.format(src));
		}
	}).setPrettyPrinting().create();
	public static String serializeObject(Object o) {
		return gson.toJson(o);
	}
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
		logger.trace("decodedToken : {}", serializeObject(accessToken));
		return accessToken;
	}

	@Override
	public void createClient(Keycloak kc, String realm, String clientId, String secret, String redirectUri, String baseURL, String webOrigins, String[] defaultRoles) {

		ClientRepresentation clientRepresentation = new ClientRepresentation();
		clientRepresentation.setClientId(clientId);
		clientRepresentation.setSecret(secret);
		clientRepresentation.setRedirectUris(Arrays.asList(redirectUri));
		clientRepresentation.setBaseUrl(baseURL);
		clientRepresentation.setWebOrigins(Arrays.asList(webOrigins));
		clientRepresentation.setDirectAccessGrantsEnabled(true);
		clientRepresentation.setServiceAccountsEnabled(true);
		clientRepresentation.setAuthorizationServicesEnabled(true);
		clientRepresentation.setEnabled(true);
		clientRepresentation.setPublicClient(false);
		clientRepresentation.setDefaultRoles(defaultRoles);
		kc.realms().realm(realm).clients().create(clientRepresentation);
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
	public TokenSet getTokenClient(String URI,  String client_id, String client_credential)
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
