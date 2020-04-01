package org.sinaure.instantsecurity.rest;

import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.sinaure.instantsecurity.config.SecurityContextUtils;
import org.sinaure.instantsecurity.model.RealmInstantApp;
import org.sinaure.instantsecurity.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/instant")
public class KcController {
  static final Logger logger = LogManager.getLogger(KcController.class.getName());
  @Autowired
  private AuthService authService;
  @Autowired
  private Keycloak kc;
  @GetMapping(path = "/app/{app}/user/name")
  public ResponseEntity<String> getAuthorizedUserName(@PathVariable String app) {
    return ResponseEntity.ok(SecurityContextUtils.getUserName());
  }

  @GetMapping(path = "/app/{app}/user/roles")
  public ResponseEntity<Set<String>> getAuthorizedUserRoles(@PathVariable String app) {
    return ResponseEntity.ok(SecurityContextUtils.getUserRoles());
  }
  @PostMapping(path = "/editor/realm")
  public ResponseEntity<RealmRepresentation> createRealm(@RequestBody RealmInstantApp realm) {
    try{
      if(kc.realms().findAll().stream().filter(r -> r.getId().equalsIgnoreCase(realm.getIdRealm())).findFirst().isPresent()){
        logger.error("already existing realm : {}",realm.getIdRealm());
        return new ResponseEntity<RealmRepresentation>(kc.realms().realm(realm.getIdRealm()).toRepresentation(), HttpStatus.OK);
      }
      authService.createRealm(kc,realm);
      return ResponseEntity.ok(kc.realms().realm(realm.getIdRealm()).toRepresentation());
    } catch(Exception e){
      logger.error(e.getMessage());

    }
    return new ResponseEntity<RealmRepresentation>(new RealmRepresentation(), HttpStatus.UNAUTHORIZED);
  }
  @PostMapping(path = "/editor/realm/{realmId}")
  public ResponseEntity<ClientRepresentation> createClient(@PathVariable String realmId , @RequestBody ClientRepresentation clientRepresentation) {
    //clients on created application specific realms just have USER role

    try{
      if(!kc.realms().findAll().stream().filter(r -> r.getId().equalsIgnoreCase(realmId)).findFirst().isPresent()){
        logger.error("realm {} does not exist! create it first",realmId);
        return new ResponseEntity<ClientRepresentation>(new ClientRepresentation(), HttpStatus.NOT_FOUND);
      }
      authService.createClient(kc,realmId,clientRepresentation,new String[]{"USER"});
      return ResponseEntity.ok(kc.realms().realm(realmId).clients().findByClientId(clientRepresentation.getClientId()).get(0));
    } catch(Exception e){
      e.printStackTrace();
      logger.error(e.getMessage());
    }
    return new ResponseEntity<ClientRepresentation>(new ClientRepresentation(), HttpStatus.UNAUTHORIZED);
  }
  @PostMapping(path = "/editor/realm/{realmId}/client/{clientId}")
  public ResponseEntity<Set<String>> createUser() {
    //TODO
    return ResponseEntity.ok(SecurityContextUtils.getUserRoles());
  }
  @GetMapping(path = "/editor/realm/{realmId}/client/{clientId}")
  public ResponseEntity<Set<String>> listUsers() {
    //TODO
    return ResponseEntity.ok(SecurityContextUtils.getUserRoles());
  }
}
