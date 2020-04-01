package org.sinaure.instantsecurity.rest;

import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.sinaure.instantsecurity.config.SecurityContextUtils;
import org.sinaure.instantsecurity.model.RealmInstantApp;
import org.sinaure.instantsecurity.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/")
public class KcController {
  static final Logger logger = LogManager.getLogger(KcController.class.getName());
  @Autowired
  private AuthService authService;
  @Autowired
  @Qualifier("kc")
  private Keycloak kc;
  @Autowired
  @Qualifier("kc_lime")
  private Keycloak kc_lime;

  @GetMapping(path = "/app/{app}/user/name")
  public ResponseEntity<String> getAuthorizedUserName(@PathVariable String app) {
    return ResponseEntity.ok(SecurityContextUtils.getUserName());
  }

  @GetMapping(path = "/app/{app}/user/roles")
  public ResponseEntity<Set<String>> getAuthorizedUserRoles(@PathVariable String app) {
    return ResponseEntity.ok(SecurityContextUtils.getUserRoles());
  }
  @GetMapping(path = "/app/realm/{realmId}/client/{clientId}")
  public ResponseEntity<List<UserRepresentation>> listUsers(@PathVariable String realmId) {
    return ResponseEntity.ok(kc.realms().realm(realmId).users().list());
  }

  @PostMapping(path = "/instant/realm")
  public ResponseEntity<RealmRepresentation> createRealm(@RequestBody RealmInstantApp realm) {
    try{
      if(kc.realms().findAll().stream().filter(r -> r.getId().equalsIgnoreCase(realm.getIdRealm())).findFirst().isPresent()){
        logger.error("already existing realm : {}",realm.getIdRealm());
        return new ResponseEntity<RealmRepresentation>(kc.realms().realm(realm.getIdRealm()).toRepresentation(), HttpStatus.OK);
      }
      authService.createRealm(kc,realm);

    } catch(Exception e){
      logger.error(e.getMessage());

    }
    return ResponseEntity.ok(kc.realms().realm(realm.getIdRealm()).toRepresentation());
  }
  @PostMapping(path = "/instant/realm/{realmId}")
  public ResponseEntity<ClientRepresentation> createClient(@PathVariable String realmId , @RequestBody ClientRepresentation clientRepresentation) {
    //clients on created application specific realms just have USER role

    try{
      if(!kc.realms().findAll().stream().filter(r -> r.getId().equalsIgnoreCase(realmId)).findFirst().isPresent()){
        logger.error("realm {} does not exist! create it first",realmId);
        return new ResponseEntity<ClientRepresentation>(new ClientRepresentation(), HttpStatus.NOT_FOUND);
      }
      authService.createClient(kc,realmId,clientRepresentation,clientRepresentation.getDefaultRoles());

    } catch(Exception e){
      e.printStackTrace();
      logger.error(e.getMessage());
    }
    return ResponseEntity.ok(kc.realms().realm(realmId).clients().findByClientId(clientRepresentation.getClientId()).get(0));
  }
  @PostMapping(path = "/instant/realm/{realmId}/client/{clientId}")
  public ResponseEntity<UserRepresentation> createUser(@RequestBody UserRepresentation userRepresentation, @PathVariable String clientId, @PathVariable String realmId ) {
    if(authService.createUser(kc_lime,realmId,clientId, userRepresentation)){
      ResponseEntity.ok(userRepresentation);
    }
    return ResponseEntity.badRequest().body(new UserRepresentation());
  }

}
