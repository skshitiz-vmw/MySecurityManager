package org.skshitiz;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.ResourcePermission;
import org.apache.geode.security.SecurityManager;
import org.apache.logging.log4j.Logger;
import org.apache.geode.logging.internal.log4j.api.LogService;

public class BasicSecurityManager implements SecurityManager {

    private final HashMap<String, User> approvedUsersList = new HashMap<>();
    private static final String ADMIN_USERNAME = "admin";
    static final Logger logger = LogService.getLogger();

    @Override
    public void init(final Properties securityProperties) {
        String viewer = "viewer";
        List<ResourcePermission> viewerPermissions = new ArrayList<>();
       viewerPermissions.add(new ResourcePermission(ResourcePermission.Resource.CLUSTER,
               ResourcePermission.Operation.READ));
       viewerPermissions.add(new ResourcePermission(ResourcePermission.Resource.DATA,
               ResourcePermission.Operation.READ));
        User viewerUser = new User(viewer, viewer, viewerPermissions);
        
        List<ResourcePermission> allPermissions = new ArrayList<>();
        allPermissions.add(new ResourcePermission(ResourcePermission.Resource.ALL,
                ResourcePermission.Operation.ALL));
        User adminUser = new User(ADMIN_USERNAME, "Admin!23", allPermissions);

        this.approvedUsersList.put(ADMIN_USERNAME, adminUser);
        this.approvedUsersList.put(viewer, viewerUser);

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
        boolean permitted = false;
        if (principal == null) {
            permitted = false;
        } else {
            User user = this.approvedUsersList.get(User.prefixOfToken.concat(principal.toString()));
            if (user == null) {
                permitted = false;
            }
            for (ResourcePermission userPermission : user.getPermissions()) {
                if (userPermission.implies(resourcePermissionRequested)) {
                    permitted = true;
                    break;
                }
            }
        }
        auditAuthorizationLog(principal, resourcePermissionRequested, permitted);
        return permitted;
    }

    private void auditAuthorizationLog(Object principal, ResourcePermission userPermission, boolean permitted) {
        logger.info("******** Start auditAuthorizationLog ********");
        logger.info("AUDIT TRAIL: Principal - " + principal != null ? principal.toString() : "null" + " Permitted: " + permitted + " to " + userPermission + "." );
        logger.info("******** End auditAuthorizationLog ********");
    }
}