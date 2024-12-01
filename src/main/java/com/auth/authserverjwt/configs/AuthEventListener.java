package com.auth.authserverjwt.configs;

import com.auth.authserverjwt.services.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class AuthEventListener {

    private final UserService userService;
    private static final Logger logger = LoggerFactory.getLogger(AuthEventListener.class);

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        if (event.getException() instanceof BadCredentialsException) {
            logger.debug("{} Authentication even listener, message: {}",
                    LocalDateTime.now(), event.getException().getMessage());
            this.userService.checkLoginAttempts(event.getAuthentication().getPrincipal().toString());
        }
    }
}
