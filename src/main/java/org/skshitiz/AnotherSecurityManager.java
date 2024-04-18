package org.skshitiz;

import org.apache.geode.security.AuthenticationFailedException;
import org.apache.geode.security.ResourcePermission;
import org.apache.geode.security.SecurityManager;
import org.apache.logging.log4j.Logger;
import org.apache.geode.logging.internal.log4j.api.LogService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

public class AnotherSecurityManager implements SecurityManager {

    private final HashMap<String, User> approvedUsersList = new HashMap<>();
  
    static final Logger logger = LogService.getLogger();


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

        this.approvedUsersList.put(User.prefixOfToken.concat("operator"), operator);
        this.approvedUsersList.put(User.prefixOfToken.concat("appDeveloper"), appDeveloper);

    }

    @Override
    public Object authenticate(Properties credentials) throws AuthenticationFailedException {
        logger.info("Properties: {}, approvedUsersList: {}",credentials, approvedUsersList);
        String tokenPassedIn = credentials.getProperty(TOKEN);
        logger.info(":DEBUG: Extracted {} using {} from properties.", tokenPassedIn, TOKEN);
        User authenticatedUser = this.approvedUsersList.get(tokenPassedIn);
        if (authenticatedUser == null) {
            logger.error("Authenticated User Found NULL, {}, {}", tokenPassedIn, approvedUsersList);
            throw new AuthenticationFailedException("Invalid token, found user null");
        }
        if (!authenticatedUser.getUserToken().endsWith(authenticatedUser.toString())) {
            logger.error("Authenticated Invalid Token, {}, {}", tokenPassedIn, approvedUsersList);
            throw new AuthenticationFailedException("Sorry, Passed token is invalid or expired!");
        }
        logger.info("Login successful");
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
            } else {
                for (ResourcePermission userPermission : user.getPermissions()) {
                    if (userPermission.implies(resourcePermissionRequested)) {
                        permitted = true;
                        break;
                    }
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