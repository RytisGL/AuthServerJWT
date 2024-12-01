package com.auth.authserverjwt.services;

import com.auth.authserverjwt.dto.*;
import com.auth.authserverjwt.entities.RefreshToken;
import com.auth.authserverjwt.entities.User;
import com.auth.authserverjwt.exceptions.exceptionscutom.BadRequestException;
import com.auth.authserverjwt.exceptions.exceptionscutom.RefreshTknExpireException;
import com.auth.authserverjwt.exceptions.exceptionscutom.UniqueEmailException;
import com.auth.authserverjwt.repositories.RefreshTokenRepository;
import com.auth.authserverjwt.repositories.UserRepository;
import com.auth.authserverjwt.testutils.TestUtils;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
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
    private final Long id = 1L;
    private PasswordChangeRequest passwordChangeRequest;
    private MockHttpServletResponse  responseMock;
    private MockHttpServletRequest requestMock;

    @BeforeEach
    public void setup() {
        this.user = TestUtils.getTestUser();
        this.authenticationRequest = TestUtils.getAuthenticationRequest();
        this.registrationRequest = TestUtils.getRegistrationRequest();
        this.refreshToken = TestUtils.getRefreshToken();
        this.passwordChangeRequest = TestUtils.getTestPasswordChangeRequest();
        this.responseMock = new MockHttpServletResponse();
        this.requestMock = new MockHttpServletRequest();
    }

    @BeforeEach
    public void initSecurityContext() {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("test@test.test",
                "password"));
    }

    @Test
    void testRegisterSuccess() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(jwtService.generateToken(any(User.class))).thenReturn("jwtToken");
        when(userRepository.saveAndFlush(any(User.class))).thenReturn(user);

        AuthenticationResponse authenticationResponse = userService.register(registrationRequest, responseMock);

        assertNotNull(authenticationResponse);
        assertEquals("jwtToken", authenticationResponse.getJwtToken());
        assertNotNull(responseMock.getCookie("refreshToken"));
        assertNotNull(authenticationResponse.getExpiresIn());
        verify(userRepository).saveAndFlush(any(User.class));
    }

    @Test
    void testRegisterEmailAlreadyExists() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));

        assertThrows(UniqueEmailException.class, () -> userService.register(registrationRequest, responseMock));
        verify(userRepository, never()).saveAndFlush(any(User.class));
    }

    @Test
    void testAuthenticateSuccess() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(null);
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));
        when(jwtService.generateToken(any(User.class))).thenReturn("jwtToken");

        AuthenticationResponse response = userService.authenticate(authenticationRequest, responseMock);

        assertNotNull(response);
        assertEquals("jwtToken", response.getJwtToken());
        assertNotNull(responseMock.getCookie("refreshToken"));
        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    void testAuthenticateBadCredentialsException() {
        AuthenticationRequest request = new AuthenticationRequest(authenticationRequest.getEmail(),
                authenticationRequest.getPassword());

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThrows(BadCredentialsException.class, () -> userService.authenticate(request, responseMock));

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
        verify(userRepository, never()).delete(user);
    }

    @Test
    void testRefreshTokenSuccess() {
        requestMock.setCookies(new Cookie("refreshToken", "test"));
        when(this.refreshTokenRepository.findByToken(anyString())).thenReturn(refreshToken);
        when(this.jwtService.generateToken(any(UserDetails.class))).thenReturn("JWT token");

        AuthenticationResponse authenticationResponse = this.userService.refreshToken(requestMock);

        assertEquals("JWT token", authenticationResponse.getJwtToken());
    }

    @Test
    void testRefreshTokenBadCredentialException() {
        requestMock.setCookies(new Cookie("refreshToken", "test"));
        when(this.refreshTokenRepository.findByToken(anyString())).thenReturn(null);

        assertThrows(BadCredentialsException.class, () -> this.userService.refreshToken(requestMock));
    }

    @Test
    void testRefreshTokenRefreshTknExpiredException() {
        requestMock.setCookies(new Cookie("refreshToken", "test"));
        refreshToken.setExpiresAt(Instant.now().minusSeconds(60));

        when(this.refreshTokenRepository.findByToken(any())).thenReturn(refreshToken);

        assertThrows(RefreshTknExpireException.class, () -> this.userService.refreshToken(requestMock));
    }

    @Test
    void testChangeUserExpiredStatusByIdSuccessFalse() {
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        UserResponse userResponse = this.userService.changeExpiredStatusById(id, "false");

        assertTrue(userResponse.isManuallyNonLocked());
        verify(userRepository, times(1)).saveAndFlush(user);
    }

    @Test
    void testChangeUserExpiredStatusByIdSuccessTrue() {
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        UserResponse userResponse = this.userService.changeExpiredStatusById(id, "true");

        assertFalse(userResponse.isManuallyNonLocked());
        verify(userRepository, times(1)).saveAndFlush(user);
    }

    @Test
    void testChangeUserExpiredStatusByIdBadRequestException() {
        when(userRepository.findById(id)).thenReturn(Optional.of(user));
        assertThrows(BadRequestException.class, () -> this.userService.changeExpiredStatusById(id, "test"));

        verify(userRepository, never()).saveAndFlush(any(User.class));
    }

    @Test
    void testChangeUserExpiredStatusByIdNoSuchElementException() {
        when(userRepository.findById(id)).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> this.userService.changeExpiredStatusById(id, "test"));

        verify(userRepository, never()).saveAndFlush(any(User.class));
    }

    @Test
    void testChangePasswordSuccess() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

        String result = this.userService.changePassword(passwordChangeRequest);

        assertEquals("Password changed", result);
        verify(userRepository, times(1)).saveAndFlush(user);
    }

    @Test
    void testChangePasswordWrongPassword() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        String result = this.userService.changePassword(passwordChangeRequest);

        assertEquals("Wrong password", result);
        verify(userRepository, never()).saveAndFlush(user);
    }

    @Test
    void testChangePasswordNoSuchElementException() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> this.userService.changePassword(passwordChangeRequest));
    }

    @Test
    void testChangeUserAuthorityByIdSuccess() {
        when(userRepository.findById(id)).thenReturn(Optional.of(user));

        UserResponse userResponse = this.userService.changeUserAuthorityById(id, "test");

        assertEquals("test", userResponse.getAuthority());
        verify(userRepository, times(1)).saveAndFlush(user);
    }

    @Test
    void testChangeUserAuthorityByIdNoSuchElementException() {
        when(userRepository.findById(id)).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> this.userService.changeUserAuthorityById(id, "test"));

        verify(userRepository, never()).saveAndFlush(any(User.class));
    }
}