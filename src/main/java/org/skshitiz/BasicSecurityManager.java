package org.skshitiz;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.ResourcePermission;
import org.apache.geode.security.SecurityManager;

public class BasicSecurityManager implements SecurityManager {

    private final HashMap<String, User> approvedUsersList = new HashMap<>();
    private static final String ADMIN_USERNAME = "skshitiz";

    @Override
    public void init(final Properties securityProperties) {
        String konica = "konica";
        List<ResourcePermission> viewerPermissions = new ArrayList<>();
        viewerPermissions.add(new ResourcePermission(ResourcePermission.Resource.CLUSTER,
                ResourcePermission.Operation.READ));
        viewerPermissions.add(new ResourcePermission(ResourcePermission.Resource.DATA,
                ResourcePermission.Operation.READ));
        User viewer = new User(konica, konica, viewerPermissions);
        
        List<ResourcePermission> allPermissions = new ArrayList<>();
        allPermissions.add(new ResourcePermission(ResourcePermission.Resource.ALL,
                ResourcePermission.Operation.ALL));
        User adminUser = new User(ADMIN_USERNAME, "Admin!23", allPermissions);

        this.approvedUsersList.put(ADMIN_USERNAME, adminUser);
        this.approvedUsersList.put(konica, viewer);

    }

    @Override
    public Object authenticate(Properties credentials) throws AuthenticationFailedException {
        String usernamePassedIn = credentials.getProperty(USER_NAME);
        String passwordPassedIn = credentials.getProperty(PASSWORD);
        String tokenPassedIn = credentials.getProperty(TOKEN);
        if(tokenPassedIn!=null && tokenPassedIn.contains(ADMIN_USERNAME)) {
            return this.approvedUsersList.get(ADMIN_USERNAME);
        }
        User authenticatedUser = this.approvedUsersList.get(usernamePassedIn);
        if (authenticatedUser == null) {
            if (tokenPassedIn != null) {
                throw new AuthenticationFailedException("Sorry, your authentication token is invalid or has expired. Please log in again.");
            } else {
                throw new AuthenticationFailedException("Authentication Required!");
            }
        }
        if (!authenticatedUser.getUserPassword().equals(passwordPassedIn) && !"".equals(usernamePassedIn)) {
            throw new AuthenticationFailedException("Sorry, the username or password you entered is incorrect. Please try again.");
        }
        return authenticatedUser;
    }

    @Override
    public boolean authorize(Object principal, ResourcePermission resourcePermissionRequested) {
        if (principal == null) {
            return false;
        }
        User user = this.approvedUsersList.get(principal.toString());
        if (user == null) {
            return false;
        }
        for (ResourcePermission userPermission : user.getPermissions()) {
            if (userPermission.implies(resourcePermissionRequested)) {
                return true;
            }
        }
        return false;
    }

}