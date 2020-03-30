package org.sinaure.instantsecurity;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.common.VerificationException;
import org.sinaure.instantsecurity.services.AuthService;
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
import java.util.Optional;

@RunWith(SpringRunner.class)
@SpringBootTest
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ApiTests extends AbstractKeycloakTest{
  static final Logger logger = LogManager.getLogger(ApiTests.class.getName());
  @Autowired
  private AuthService authService;
  @Autowired
  private RestTemplate restTemplate;
  private static Keycloak kc = null;
  //get TOKEN
  private static TokenSet tokenSet = null;
  private static String apiEndpoint = "http://localhost:8085/api/v1/employees/username";

  @Rule
  public ExpectedException exceptionRule = ExpectedException.none();

  // IF CLIENT IS CONFIDENTIAL THIS CAN'T WORK NEED TO TEST IT MANUALLY WITH AUTHENTICATION CODE FLOW USING POSTMAN
  @Test
  public void test1_getTokenUser() throws UserUnauthorizedException {
    exceptionRule.expect(UserUnauthorizedException.class);
    exceptionRule.expectMessage("can't get token : Unauthorized");
    String keycloakUrl = keycloakhost + "/auth/realms/" + realm_instant + "/protocol/openid-connect/token";
    TokenSet tokenSet = authService.getToken(keycloakUrl, "aureliano", "sinatra", client_instant);
    logger.info(tokenSet.getAuthToken());
  }

  @Test
  public void test2_getTokenClient() throws UserUnauthorizedException {

    String keycloakUrl = keycloakhost + "/auth/realms/" + realm_instant + "/protocol/openid-connect/token";

    tokenSet = authService.getTokenClient(keycloakUrl, client_instant,client_instant_secret );
    logger.info(tokenSet.getAuthToken());
    Assert.assertNotNull(tokenSet);
  }

  // use service account to login : it have to be present the ROLE EDITOR in client -> service accounts
  @Test
  public void test3_performGetToProtectedAPI() throws UserUnauthorizedException {
    //check response from security REST API
    HttpHeaders headers = new HttpHeaders();
    headers.set("Authorization", "Bearer " + tokenSet.getAuthToken());
    try {
      logger.info("performing GET to {}", getUriApp(realm_instant));
      ResponseEntity<String> response = restTemplate.exchange(apiEndpoint, HttpMethod.GET, new HttpEntity<Object>(headers), String.class);
      logger.info("response body:  {} ", response.getBody());
    } catch (Exception e) {
      e.printStackTrace();
      logger.info(e.getMessage());
      throw new UserUnauthorizedException("can't access API : Unauthorized");
    }
  }





}
