package com.auth.authserverjwt.utils;

import org.springframework.security.core.context.SecurityContextHolder;

public abstract class Utils {
    private Utils() {}

    public static String getSecurityContextHolderName() {
        return SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
