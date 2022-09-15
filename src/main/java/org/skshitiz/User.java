package org.skshitiz;

import java.io.Serializable;
import java.util.List;

import org.apache.geode.security.ResourcePermission;

public class User implements Serializable {

    static final String prefixOfToken = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-";
    private List<ResourcePermission> userPermissions;
    private String userName;
    private String userPassword;
    private String userToken;

    public User(String userName, String userPassword, List<ResourcePermission> userPermissions) {
        this.userName = userName;
        this.userPassword = userPassword;
        this.userPermissions = userPermissions;
        this.userToken = prefixOfToken.concat(userName);
    }

    public String getUserPassword() {
        return userPassword;
    }

    @Override
    public String toString() {
        return userName;
    }

    public String getUserToken() {
        return userToken;
    }

    public void setUserToken(String userToken) {
        this.userToken = userToken;
    }

    public List<ResourcePermission> getPermissions() {
        return this.userPermissions;
    }

    public boolean hasPermission(ResourcePermission resourcePermissionRequested) {
        boolean hasPermission = false;

        for (ResourcePermission userPermission : userPermissions) {
            if (userPermission.implies(resourcePermissionRequested)) {
                hasPermission = true;
                break;
            }
        }
        return hasPermission;
    }
}