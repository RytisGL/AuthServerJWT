package com.auth.authserverjwt.configs;

import com.auth.authserverjwt.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationEvents {
    private final UserService userService;

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        if (event.getException() instanceof BadCredentialsException) {
            this.userService.checkLoginAttempts(event.getAuthentication().getPrincipal().toString());
        }
    }
}
