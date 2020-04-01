package org.sinaure.instantsecurity;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.idm.*;
import org.sinaure.instantsecurity.config.SecurityContextUtils;
import org.sinaure.instantsecurity.model.RealmInstantApp;
import org.sinaure.instantsecurity.services.AuthService;
import org.sinaure.instantsecurity.services.ResourceAlreadyExistException;
import org.sinaure.instantsecurity.services.TokenSet;
import org.sinaure.instantsecurity.services.UserUnauthorizedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import static java.util.Arrays.asList;

@RunWith(SpringRunner.class)
@SpringBootTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class ApiTests extends AbstractKeycloakTest{
  static final Logger logger = LogManager.getLogger(ApiTests.class.getName());
  @Autowired
  private AuthService authService;
  @Autowired
  private RestTemplate restTemplate;

  static TokenSet tokenSet = null;
  static String apiEndpointUsername = "http://localhost:8085/api/v1/app/lime/user/name";
  static String apiEndpointRealm = "http://localhost:8085/api/v1/instant/realm";

  static String apiEndpointInstantUserCreate = "http://localhost:8085/api/v1/instant/realm/lime/client/lime";
  static String apiEndpointApp = "http://localhost:8085/api/v1/app/realm/lime/client/lime";
  @Rule
  public ExpectedException exceptionRule = ExpectedException.none();

  @Test
  @Order(1)
  public void test1_getTokenInstantClient() throws UserUnauthorizedException {

    String keycloakUrl = keycloakhost + "/auth/realms/" + realm_instant + "/protocol/openid-connect/token";

    tokenSet = authService.getTokenClient(keycloakUrl, client_instant,client_instant_secret );
    logger.info(tokenSet.getAuthToken());
    Assert.assertNotNull(tokenSet);
  }

  // use service account to login : it have to be present the ROLE SUPERADMIN in client -> service accounts
  // create a REALM + CLIENT + composite ROLE manage-users ONLY, store pubkey and secret to an external DB eventually sync it with VAULT
  @Test
  @Order(2)
  public void test2_performPostToProtectedInstantAPI() throws InvalidKeySpecException, VerificationException, NoSuchAlgorithmException, IOException, UserUnauthorizedException {
    String keycloakUrl = keycloakhost + "/auth/realms/" + realm_instant + "/protocol/openid-connect/token";
    tokenSet = authService.getTokenClient(keycloakUrl, client_instant,client_instant_secret );
    logger.info(tokenSet.getAuthToken());
    Assert.assertNotNull(tokenSet);

    //1. create REALM
    RealmInstantApp realm = new RealmInstantApp();
    realm.setIdRealm(realm_1);
    realm.setRealm(realm_1);
    realm.setRoles(appRoles);
    logger.info(SecurityContextUtils.serializeObject(realm));
    //check response from security REST API
    HttpHeaders headers = new HttpHeaders();
    headers.set("Authorization", "Bearer " + tokenSet.getAuthToken());
    authService.decodeJWT(keycloakhost,tokenSet.getAuthToken(),realm_instant,pubKeyInstant);
    try {
      logger.info("performing POST to {}", apiEndpointRealm);
      ResponseEntity<String> response = restTemplate.postForEntity(apiEndpointRealm,  new HttpEntity<RealmInstantApp>(realm,headers), String.class);
      logger.info("response body:  {} ", response.getBody());
      Assert.assertNotNull(response.getBody());
    } catch (Exception e) {
      e.printStackTrace();
      logger.info(e.getMessage());
      logger.info("Resource realm : "+realm_1+" already exist -- SKIP creation");
    }

    //2. create confidential CLIENT on new realm
    ClientRepresentation clientRepresentation = new ClientRepresentation();
    clientRepresentation.setClientId(client_id_1);
    clientRepresentation.setSecret(client_secret_1);
    clientRepresentation.setRedirectUris(Arrays.asList(redirectUri));
    clientRepresentation.setBaseUrl(baseURL);
    clientRepresentation.setWebOrigins(Arrays.asList(webOrigins));
    clientRepresentation.setDirectAccessGrantsEnabled(true);
    clientRepresentation.setServiceAccountsEnabled(true);
    clientRepresentation.setAuthorizationServicesEnabled(true);
    clientRepresentation.setEnabled(true);
    clientRepresentation.setPublicClient(false);

    logger.info(SecurityContextUtils.serializeObject(clientRepresentation));

    //check response from security REST API
    try {
      logger.info("performing POST to {}", apiEndpointRealm);
      ResponseEntity<String> response = restTemplate.postForEntity(apiEndpointRealm+"/"+realm_1,new HttpEntity<ClientRepresentation>(clientRepresentation,headers), String.class);
      logger.info("response body:  {} ", response.getBody());
      Assert.assertNotNull(response.getBody());
    } catch (Exception e) {
      e.printStackTrace();
      logger.info(e.getMessage());
      logger.info("Resource client : "+clientRepresentation.getClientId()+" already exist -- SKIP creation");
    }

    //3. create public CLIENT
    ClientRepresentation clientRepresentation2 = new ClientRepresentation();
    clientRepresentation2.setClientId(client_id_1+"_pub");
    clientRepresentation2.setEnabled(true);
    clientRepresentation2.setPublicClient(true);
    clientRepresentation2.setDefaultRoles(appRoles);

    logger.info(SecurityContextUtils.serializeObject(clientRepresentation));

    //check response from security REST API
    try {
      logger.info("performing POST to {}", apiEndpointRealm);
      ResponseEntity<String> response = restTemplate.postForEntity(apiEndpointRealm+"/"+realm_1, new HttpEntity<ClientRepresentation>(clientRepresentation2,headers), String.class);
      logger.info("response body:  {} ", response.getBody());
      Assert.assertNotNull(response.getBody());
    } catch (Exception e) {
      e.printStackTrace();
      logger.info(e.getMessage());
      logger.info("Resource client : "+clientRepresentation2.getClientId()+" already exist -- SKIP creation");
    }
  }


  // use service account to login : USE THE CONFIDENTIAL CLIENT CREATED ON INSTANT REALM TO AUTHENTICATE (it have to stay there because of Pubkey)
  @Test
  @Order(3)
  public void test3_performUserCreationToProtectedInstantAPI() throws UserUnauthorizedException, InvalidKeySpecException, VerificationException, NoSuchAlgorithmException, IOException {

    String keycloakUrl = keycloakhost + "/auth/realms/" + realm_instant + "/protocol/openid-connect/token";
    tokenSet = authService.getTokenClient(keycloakUrl, client_instant,client_instant_secret  );
    Assert.assertNotNull(tokenSet);

    logger.info(tokenSet.getAuthToken());
    HttpHeaders headers = new HttpHeaders();
    authService.decodeJWT(keycloakhost,tokenSet.getAuthToken(),realm_instant,pubKeyInstant);
    headers.set("Authorization", "Bearer " + tokenSet.getAuthToken());
    //CREATE users on App Realm
    UserRepresentation userRepresentation = new UserRepresentation();
    userRepresentation.setEnabled(true);
    String username = "jroquay_"+RandomStringUtils.randomAlphanumeric(10);
    userRepresentation.setUsername(username);
    userRepresentation.setFirstName(username);
    userRepresentation.setLastName(username);
    userRepresentation.setEmail(username+"@instant.com");


    try {
      logger.info("performing POST to {}", apiEndpointInstantUserCreate);
      ResponseEntity<String> response = restTemplate.exchange(apiEndpointInstantUserCreate, HttpMethod.POST, new HttpEntity<Object>(userRepresentation,headers), String.class);
      logger.info("response body:  {} ", response.getBody());
      Assert.assertNotNull(response.getBody());
    } catch (Exception e) {
      e.printStackTrace();
      logger.info(e.getMessage());
      throw new UserUnauthorizedException("can't access API : Unauthorized");
    }
  }
  // use USER authentication via authentication code :
  @Test
  @Order(4)
  public void test4_performGetToProtectedUserAPI() throws UserUnauthorizedException {
    //Create users on App Realm LIME using MASTER admin-cli credentials

    //Get all users in App Realm LIME using MASTER admin-cli credentials

    //Create users on App Realm LIME using INSTANT instant credentials

    //Get all users in App Realm LIME using INSTANT instant credentials

    // Check cant CREATE users on
    //check response from security REST API
    HttpHeaders headers = new HttpHeaders();
    headers.set("Authorization", "Bearer " + tokenSet.getAuthToken());
    try {
      logger.info("performing GET to {}", apiEndpointApp);
      ResponseEntity<String> response = restTemplate.exchange(apiEndpointApp, HttpMethod.GET, new HttpEntity<Object>(headers), String.class);
      logger.info("response body:  {} ", response.getBody());
      Assert.assertNotNull(response.getBody());
    } catch (Exception e) {
      e.printStackTrace();
      logger.info(e.getMessage());
      throw new UserUnauthorizedException("can't access API : Unauthorized");
    }
  }









}
