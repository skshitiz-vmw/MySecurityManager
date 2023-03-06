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

    @Override
    public void init(final Properties securityProperties) {

        List<ResourcePermission> operatorPermissions = new ArrayList<>();
        operatorPermissions.add(new ResourcePermission(ResourcePermission.Resource.CLUSTER,
                ResourcePermission.Operation.MANAGE));
        operatorPermissions.add(new ResourcePermission(ResourcePermission.Resource.CLUSTER,
                ResourcePermission.Operation.WRITE));
        operatorPermissions.add(new ResourcePermission(ResourcePermission.Resource.CLUSTER,
                ResourcePermission.Operation.READ));

        User operator = new User("operator", "secret", operatorPermissions);

        List<ResourcePermission> appDevPermissions = new ArrayList<>();
        appDevPermissions.add(new ResourcePermission(ResourcePermission.Resource.CLUSTER,
                ResourcePermission.Operation.READ));
        appDevPermissions.add(new ResourcePermission(ResourcePermission.Resource.DATA,
                ResourcePermission.Operation.MANAGE));
        appDevPermissions.add(new ResourcePermission(ResourcePermission.Resource.DATA,
                ResourcePermission.Operation.WRITE));
        appDevPermissions.add(new ResourcePermission(ResourcePermission.Resource.DATA,
                ResourcePermission.Operation.READ));

        User appDeveloper = new User("appDeveloper", "NotSoSecret", appDevPermissions);

        List<ResourcePermission> allPermissions = new ArrayList<>();
        appDevPermissions.add(new ResourcePermission(ResourcePermission.Resource.ALL,
                ResourcePermission.Operation.ALL));
        User adminUser = new User("skshitiz", "Admin!23", allPermissions);

        this.approvedUsersList.put("skshitiz", adminUser);
        this.approvedUsersList.put("operator", operator);
        this.approvedUsersList.put("appDeveloper", appDeveloper);

    }

    @Override
    public Object authenticate(Properties credentials) throws AuthenticationFailedException {

        String usernamePassedIn = credentials.getProperty(USER_NAME);
        String passwordPassedIn = credentials.getProperty(PASSWORD);
        String tokenPassedIn = credentials.getProperty(TOKEN);

        User authenticatedUser = this.approvedUsersList.get(usernamePassedIn);

        if (authenticatedUser == null) {
            throw new AuthenticationFailedException("Authentication Required!");
        }

        if (tokenPassedIn != null && !tokenPassedIn.isEmpty()) {
            throw new AuthenticationFailedException("Sorry, your authentication token is invalid or has expired. Please log in again.");
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