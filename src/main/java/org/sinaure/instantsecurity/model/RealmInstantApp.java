package org.sinaure.instantsecurity.model;

public class RealmInstantApp {
    private String idRealm;
    private String realm;

    public String getIdRealm() {
        return idRealm;
    }

    public void setIdRealm(String idRealm) {
        this.idRealm = idRealm;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String[] getRoles() {
        return roles;
    }

    public void setRoles(String[] roles) {
        this.roles = roles;
    }

    private String[] roles;
}
