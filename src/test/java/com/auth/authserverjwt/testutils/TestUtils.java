package com.auth.authserverjwt.testutils;

import com.auth.authserverjwt.dto.AuthenticationRequest;
import com.auth.authserverjwt.dto.PasswordChangeRequest;
import com.auth.authserverjwt.dto.RegistrationRequest;
import com.auth.authserverjwt.dto.TokenRefreshRequest;
import com.auth.authserverjwt.entities.RefreshToken;
import com.auth.authserverjwt.entities.User;
import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.time.LocalDateTime;

@UtilityClass
public class TestUtils {

    public static User getTestUser() {
        return User.builder()
                .email("test@test.text")
                .password("password")
                .authority("Admin")
                .id(1L)
                .accountNonLocked(true)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .enabled(true)
                .accountNonExpired(true)
                .build();
    }

    public static PasswordChangeRequest getTestPasswordChangeRequest() {
        return PasswordChangeRequest.builder()
                .newPassword("test")
                .oldPassword("password")
                .build();
    }

    public static AuthenticationRequest getAuthenticationRequest() {
        return AuthenticationRequest.builder()
                .email("test@test.text")
                .password("password")
                .build();
    }

    public static RegistrationRequest getRegistrationRequest() {
        return RegistrationRequest.builder()
                .email("test@test.text")
                .password("password")
                .build();
    }

    public static RefreshToken getRefreshToken() {
        return RefreshToken.builder()
                .user(getTestUser())
                .token("refreshToken")
                .id(1L)
                .expiresAt(Instant.now().plusSeconds(6000))
                .createdAt(LocalDateTime.now())
                .build();
    }

    public static TokenRefreshRequest getTokenRefreshRequest() {
        return TokenRefreshRequest.builder()
                .token("Test token")
                .build();
    }
}
