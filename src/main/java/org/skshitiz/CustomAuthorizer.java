package org.skshitiz;

import java.lang.reflect.Method;

import org.apache.geode.cache.query.security.MethodInvocationAuthorizer;

public class CustomAuthorizer implements MethodInvocationAuthorizer {

    @Override
    public boolean authorize(Method method, Object target) {    
        return true;
    }
}
