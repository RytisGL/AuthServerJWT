package com.auth.authserverjwt.services;

import com.auth.authserverjwt.converters.UserConverter;
import com.auth.authserverjwt.dto.*;
import com.auth.authserverjwt.entities.RefreshToken;
import com.auth.authserverjwt.entities.User;
import com.auth.authserverjwt.exceptions.exceptionscutom.BadRequestException;
import com.auth.authserverjwt.exceptions.exceptionscutom.RefreshTknExpireException;
import com.auth.authserverjwt.exceptions.exceptionscutom.UniqueEmailException;
import com.auth.authserverjwt.repositories.RefreshTokenRepository;
import com.auth.authserverjwt.repositories.UserRepository;
import com.auth.authserverjwt.utils.Utils;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JWKSet jwkSet;
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    public AuthenticationResponse register(RegistrationRequest request, HttpServletResponse response) {
        logger.info("{} Attempting to register user with email: {}", LocalDateTime.now(), request.getEmail());

        if (this.userRepository.findByEmail(request.getEmail()).isPresent()) {
            logger.info("{} Registration failed: Email {} is already in use", LocalDateTime.now(), request.getEmail());
            throw new UniqueEmailException();
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(this.passwordEncoder.encode(request.getPassword()))
                .accountNonLocked(true)
                .enabled(true)
                .accountNonExpired(true)
                .authority("Normal")
                .build();
        userRepository.saveAndFlush(user);

        logger.info("{} User with email {} registered successfully", LocalDateTime.now(), request.getEmail());
        return createAuthResponse(user, false, response);
    }


    public AuthenticationResponse authenticate(AuthenticationRequest request, HttpServletResponse response) {
        logger.info("{} Authenticating user with email: {}", LocalDateTime.now(), request.getEmail());

        try {
            this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        } catch (LockedException ex) {
            logger.warn("{} User account is locked: {}", LocalDateTime.now(), request.getEmail());
            if (isAutoAccountLockExpired(request.getEmail())) {
                logger.info("{} Lock expired for user with email: {}", LocalDateTime.now(), request.getEmail());
                this.authenticate(request, response);
            } else {
                throw ex;
            }
        }

        User user = this.userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new EntityNotFoundException("Email does not exist"));

        logger.info("{} User {} authenticated successfully", LocalDateTime.now(), user.getEmail());

        if (user.getLoginAttempts() > 0) {
            user.setLoginAttempts(0);
            this.userRepository.saveAndFlush(user);
        }
        return createAuthResponse(user, true, response);
    }


    public List<UserResponse> getUsers(String email) {
        if (email != null) {
            logger.info("{} User list requested by {}, for email {}",
                    LocalDateTime.now(), Utils.getSecurityContextHolderName(), email);
            return List.of(UserConverter.userToUserResponse(userRepository.findByEmail(email).orElseThrow()));
        }
        logger.info("{} User list requested by {}",
                LocalDateTime.now(), Utils.getSecurityContextHolderName());
        return UserConverter.usersToUserResponses(userRepository.findAll());
    }

    public UserResponse deleteUserById(Long userId) {
        logger.info("{} User deletion requested by {}, for userId {}",
                LocalDateTime.now(), Utils.getSecurityContextHolderName(), userId);
        User user = this.userRepository.findById(userId).orElseThrow();
        this.userRepository.delete(user);
        logger.info("{} User {} has been deleted requested by {}", LocalDateTime.now(), userId, Utils.getSecurityContextHolderName());
        return UserConverter.userToUserResponse(user);
    }

    public AuthenticationResponse refreshToken(HttpServletRequest request) {
        logger.debug("{} Refreshing token from request cookies", LocalDateTime.now());
        Cookie[] cookies = request.getCookies();
        String token = null;

        if (cookies == null || cookies.length == 0) {
            logger.debug("{} Token refresh failed: No cookies found in the request", LocalDateTime.now());
            throw new BadCredentialsException("No cookies found in request");
        }

        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refreshToken")) {
                token = cookie.getValue();
                break;
            }
        }

        if (token == null) {
            logger.debug("{} Token refresh failed: No refresh token cookie found", LocalDateTime.now());
            throw new BadCredentialsException("Invalid refresh token");
        }

        RefreshToken refreshToken = this.refreshTokenRepository.findByToken(token);

        if (refreshToken == null) {
            logger.debug("{} Token refresh failed: Refresh token not found in database", LocalDateTime.now());
            throw new BadCredentialsException("Bad credentials");
        }

        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            logger.info("{} Refresh token expired for user: {}", LocalDateTime.now(), refreshToken.getUser().getEmail());
            this.refreshTokenRepository.delete(refreshToken);
            throw new RefreshTknExpireException();
        }

        logger.info("{} Refresh token validated successfully for user: {}",
                LocalDateTime.now(), refreshToken.getUser().getEmail());
        return AuthenticationResponse.builder()
                .jwtToken(jwtService.generateToken(refreshToken.getUser()))
                .expiresIn(Long.parseLong(System.getenv("JWT_EXPIRATION")))
                .build();
    }


    private AuthenticationResponse createAuthResponse(User user, boolean existingUser, HttpServletResponse response) {
        if (existingUser) {
            logger.debug("{} Checking existing user refresh token for user: {}", LocalDateTime.now(), user.getEmail());
            RefreshToken refreshToken = this.refreshTokenRepository.findByUser(user);
            if (refreshToken != null) {
                logger.debug("{} Existing user previous refresh token deleted for user: {}",
                        LocalDateTime.now(), user.getEmail());
                this.refreshTokenRepository.delete(refreshToken);
            }
        }

        createRefreshTokenCookie(response, user);

        logger.debug("{} New refresh token created for user: {}", LocalDateTime.now(), user.getEmail());
        return AuthenticationResponse.builder()
                .jwtToken(jwtService.generateToken(user))
                .expiresIn(Long.parseLong(System.getenv("JWT_EXPIRATION")))
                .build();
    }


    public String logout(HttpServletResponse response) {
        logger.debug("{} User is logging out", LocalDateTime.now());
        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setDomain("localhost");
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(0);
        response.addCookie(refreshTokenCookie);
        logger.debug("{} Logout successful: Refresh token cookie cleared", LocalDateTime.now());
        return "Logout successful";
    }


    public UserResponse changeExpiredStatusById(Long userId, String status) {
        logger.info("{} Attempting to change expiration status by user {} for user with ID: {} to status: {}",
                LocalDateTime.now(), Utils.getSecurityContextHolderName(),
                userId, status.equals("expired") ? "expired" : "non-expired");

        User user = this.userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found with ID: " + userId));

        if (!status.equals("true") && !status.equals("false")) {
            logger.info("{} Invalid status value: {}. Allowed values are 'true' or 'false'", LocalDateTime.now(), status);
            throw new BadRequestException();
        }

        boolean isExpired = status.equals("true");
        user.setAccountNonExpired(!isExpired);
        this.userRepository.saveAndFlush(user);

        logger.info("{} User with ID: {} has been marked as {}",
                LocalDateTime.now(), userId, isExpired ? "expired" : "non-expired");
        return UserConverter.userToUserResponse(user);
    }

    public String changePassword(PasswordChangeRequest request) {
        logger.info("{} Attempting password change for {}", LocalDateTime.now(), Utils.getSecurityContextHolderName());

        User user = this.userRepository.findByEmail(
                        Utils.getSecurityContextHolderName())
                .orElseThrow(() ->
                        new EntityNotFoundException("Authenticated user not found"));

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            logger.warn("{} Password change failed: old password does not match for user: {}", LocalDateTime.now(), user.getEmail());
            return "Wrong password";
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        this.userRepository.saveAndFlush(user);

        logger.info("{} Password successfully changed for user: {}", LocalDateTime.now(), user.getEmail());
        return "Password changed";
    }

    public UserResponse changeUserAuthorityById(Long userId, String authority) {
        logger.info("{} Attempting to change authority by {} for user with ID: {}, to authority: {}",
                LocalDateTime.now(), Utils.getSecurityContextHolderName(), userId, authority);

        User user = this.userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found with ID: " + userId));

        user.setAuthority(authority);
        this.userRepository.saveAndFlush(user);

        logger.info("{} Authority changed to '{}' for user with ID: {}", LocalDateTime.now(), authority, userId);
        return UserConverter.userToUserResponse(user);
    }

    public void checkLoginAttempts(String email) {
        logger.debug("{} Checking login attempts for email: {}", LocalDateTime.now(), email);
        Optional<User> userOptional = this.userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            int maxLoginAttempts = 5;

            if (user.getLoginAttempts() < maxLoginAttempts) {
                user.setLoginAttempts(user.getLoginAttempts() + 1);
                logger.debug("{} Incremented login attempts for user: {}. Current attempts: {}", LocalDateTime.now(), email,
                        user.getLoginAttempts());
            } else {
                user.setAutoLockedAt(LocalDateTime.now());
                user.setAccountNonLocked(false);
                logger.warn("{} User: {} has been auto-locked due to exceeding login attempts", LocalDateTime.now(), email);
            }
            this.userRepository.saveAndFlush(user);
        }
    }

    public boolean isAutoAccountLockExpired(String email) {
        logger.debug("{} Checking if auto-account lock expired for email: {}", LocalDateTime.now(), email);

        Optional<User> userOptional = this.userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            LocalDateTime lockTime = user.getAutoLockedAt();
            long lockDurationMinutes = 10;

            if (lockTime != null && lockTime.isBefore(LocalDateTime.now().minusMinutes(lockDurationMinutes))) {
                user.setAutoLockedAt(null);
                user.setAccountNonLocked(true);
                user.setLoginAttempts(0);
                this.userRepository.saveAndFlush(user);

                logger.debug("{} Auto-account lock expired and reset for user: {}",LocalDateTime.now(), email);
                return true;
            }
        }

        logger.warn("{} Auto-account lock not expired for email: {}", LocalDateTime.now(), email);
        return false;
    }


    public Map<String, Object> getJwks() {
        logger.info("{} Oauth 2 details requested", LocalDateTime.now());
        return this.jwkSet.toJSONObject();
    }

    private void createRefreshTokenCookie(HttpServletResponse response, User user) {
        logger.debug("{} Creating refresh token cookie for user: {}", LocalDateTime.now(), user.getEmail());
        Cookie refreshTokenCookie = new Cookie("refreshToken", this.createRefreshToken(user));
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setDomain("localhost");
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(Integer.parseInt(System.getenv("REFRESH_TOKEN_EXPIRATION")));
        response.addCookie(refreshTokenCookie);
    }

    private String createRefreshToken(User user) {
        logger.debug("{} Generating a new refresh token for user: {}", LocalDateTime.now(), user.getEmail());
        String token = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .expiresAt(Instant.now().plusMillis(Long.parseLong(System.getenv("REFRESH_TOKEN_EXPIRATION"))))
                .token(token)
                .build();
        this.refreshTokenRepository.saveAndFlush(refreshToken);

        return token;
    }
}
