package com.auth.authserverjwt.services;

import com.auth.authserverjwt.dto.*;
import com.auth.authserverjwt.entities.RefreshToken;
import com.auth.authserverjwt.entities.User;
import com.auth.authserverjwt.exceptions.exceptionscutom.RefreshTknExpireException;
import com.auth.authserverjwt.exceptions.exceptionscutom.UniqueEmailException;
import com.auth.authserverjwt.repositories.RefreshTokenRepository;
import com.auth.authserverjwt.repositories.UserRepository;
import com.auth.authserverjwt.testutils.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ContextConfiguration;

import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@ContextConfiguration(classes = {UserService.class, UserRepository.class, PasswordEncoder.class,
        RefreshTokenRepository.class, AuthenticationManager.class, JWTService.class})
class UserServiceTest {

    @InjectMocks
    private UserService userService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JWTService jwtService;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private User user;
    private AuthenticationRequest authenticationRequest;
    private RegistrationRequest registrationRequest;
    private RefreshToken refreshToken;
    private TokenRefreshRequest tokenRefreshRequest;
    private final Long id = 1L;

    @BeforeEach
    public void setup() {
        this.user = TestUtils.getTestUser();
        this.authenticationRequest = TestUtils.getAuthenticationRequest();
        this.registrationRequest = TestUtils.getRegistrationRequest();
        this.refreshToken = TestUtils.getRefreshToken();
        this.tokenRefreshRequest = TestUtils.getTokenRefreshRequest();
    }

    @Test
    void testRegisterSuccess() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(jwtService.generateToken(any(User.class))).thenReturn("jwtToken");
        when(userRepository.saveAndFlush(any(User.class))).thenReturn(user);

        AuthenticationResponse authenticationResponse = userService.register(registrationRequest);

        assertNotNull(authenticationResponse);
        assertEquals("jwtToken", authenticationResponse.getJwtToken());
        assertNotNull(authenticationResponse.getRefreshToken());
        verify(userRepository).saveAndFlush(any(User.class));
    }

    @Test
    void testRegisterEmailAlreadyExists() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));

        assertThrows(UniqueEmailException.class, () -> userService.register(registrationRequest));
        verify(userRepository, never()).saveAndFlush(any(User.class));
    }

    @Test
    void testAuthenticateSuccess() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(null);
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));
        when(jwtService.generateToken(any(User.class))).thenReturn("jwtToken");

        AuthenticationResponse response = userService.authenticate(authenticationRequest);

        assertNotNull(response);
        assertEquals("jwtToken", response.getJwtToken());
        assertNotNull(response.getRefreshToken());
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void testAuthenticateBadCredentialsException() {
        AuthenticationRequest request = new AuthenticationRequest(authenticationRequest.getEmail(),
                authenticationRequest.getPassword());

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThrows(BadCredentialsException.class, () -> {
            userService.authenticate(request);
        });

        verify(authenticationManager, times(1))
                .authenticate(argThat(token ->
                        token instanceof UsernamePasswordAuthenticationToken &&
                                token.getPrincipal().equals(authenticationRequest.getEmail()) &&
                                token.getCredentials().equals(authenticationRequest.getPassword())
                ));
    }

    @Test
    void testGetUsersByEmailSuccess() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));

        List<UserResponse> userResponse = this.userService.getUsers(user.getEmail());

        assertEquals(1, userResponse.size());
        assertEquals(user.getEmail(), userResponse.getFirst().getEmail());
    }

    @Test
    void testGetUsersSuccess() {
        when(userRepository.findAll()).thenReturn(List.of(user, user));

        List<UserResponse> userResponse = this.userService.getUsers(null);

        assertEquals(2, userResponse.size());
    }

    @Test
    void testGetUsersByIdThrowsNoSuchElementException() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> userService.getUsers("test"));

        verify(userRepository, times(1)).findByEmail(anyString());
    }

    @Test
    void testDeleteUserByIdSuccess() {
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        UserResponse userResponse = this.userService.deleteUserById(id);

        assertNotNull(userResponse);
        assertEquals(user.getEmail(), userResponse.getEmail());
        verify(userRepository, times(1)).delete(user);
    }

    @Test
    void testDeleteUserByIdNoSuchElementException() {
        when(userRepository.findById(id)).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> userService.deleteUserById(id));
        verify(userRepository, times(1)).findById(id);
    }

    @Test
    void testRefreshTokenSuccess() {
        when(this.refreshTokenRepository.findByToken(anyString())).thenReturn(refreshToken);
        when(this.jwtService.generateToken(any(UserDetails.class))).thenReturn("JWT token");

        RefreshResponse token = this.userService.refreshToken(tokenRefreshRequest);

        assertEquals("JWT token", token.getJwtToken());
    }

    @Test
    void testRefreshTokenBadCredentialException() {
        when(this.refreshTokenRepository.findByToken(anyString())).thenReturn(null);

        assertThrows(BadCredentialsException.class, () -> this.userService.refreshToken(tokenRefreshRequest));
    }

    @Test
    void testRefreshTokenRefreshTknExpiredException() {
        refreshToken.setExpiresAt(Instant.now().minusSeconds(60));

        when(this.refreshTokenRepository.findByToken(any())).thenReturn(refreshToken);

        assertThrows(RefreshTknExpireException.class, () -> this.userService.refreshToken(tokenRefreshRequest));
    }

    @Test
    void testChangeUserExpiredStatusByIdSuccess() {
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        UserResponse userResponse = this.userService.changeUserAuthorityById(id, "test");

        assertEquals("test", userResponse.getAuthority());
        verify(userRepository, times(1)).saveAndFlush(user);
    }

    @Test
    void testChangeUserExpiredStatusByIdNoSuchElementException() {
    }

    @Test
    void testChangePasswordSuccess() {
    }

    @Test
    void testChangePasswordFailure() {
    }

    @Test
    void testChangeUserAuthorityByIdSuccess() {
    }

    @Test
    void testChangeUserAuthorityByIdNoSuchElementException() {
    }

    @Test
    void checkLoginAttempts() {
    }

    @Test
    void isAutoAccountLockExpired() {
    }
}