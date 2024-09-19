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
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
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

    public AuthenticationResponse register(RegistrationRequest request) {
        if (this.userRepository.findByEmail(request.getEmail()).isPresent()) {
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

        return createAuthResponse(user, false);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        }  catch (LockedException ex) {
            if (isAutoAccountLockExpired(request.getEmail())) {
                this.authenticate(request);
            } else {
                throw ex;
            }
        }
        User user = this.userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new EntityNotFoundException("Email does not exist"));
        if (user.getLoginAttempts() > 0) {
            user.setLoginAttempts(0);
            this.userRepository.saveAndFlush(user);
        }
        return createAuthResponse(user, true);
    }

    public List<UserResponse> getUsers(String email) {
        if (email != null) {
            return List.of(UserConverter.userToUserResponse(userRepository.findByEmail(email).orElseThrow()));
        }
        return UserConverter.usersToUserResponses(userRepository.findAll());
    }

    public UserResponse deleteUserById(Long userId) {
        User user = this.userRepository.findById(userId).orElseThrow();
        this.userRepository.delete(user);
        return UserConverter.userToUserResponse(user);
    }

    public RefreshResponse refreshToken(TokenRefreshRequest request) {
        //future check returns null for sure?
        RefreshToken refreshToken = this.refreshTokenRepository.findByToken(request.getToken());

        if (refreshToken == null) {
            throw new BadCredentialsException("Bad credentials");
        }

        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            this.refreshTokenRepository.delete(refreshToken);
            throw new RefreshTknExpireException();
        }

        return new RefreshResponse(this.jwtService.generateToken(refreshToken.getUser()));
    }

    private AuthenticationResponse createAuthResponse(User user, boolean existingUser) {
        if (existingUser) {
            RefreshToken refreshToken = this.refreshTokenRepository.findByUser(user);
            if (refreshToken != null) {
                this.refreshTokenRepository.delete(refreshToken);
            }
        }

        return  AuthenticationResponse.builder()
                .jwtToken(jwtService.generateToken(user))
                .refreshToken(this.createRefreshToken(user))
                .build();
    }

    public UserResponse changeUserExpiredStatusById(Long userId, String status) {
        User user = this.userRepository.findById(userId).orElseThrow();

        if (!status.equals("true") && !status.equals("false")) {
            throw new BadRequestException();
        }

        user.setAccountNonExpired(!status.equals("true"));

        this.userRepository.saveAndFlush(user);
        return UserConverter.userToUserResponse(user);
    }

    public String changePassword(PasswordChangeRequest request) {
        //Weird situation if exception thrown, what to do?
        User user = this.userRepository.findByEmail(
                SecurityContextHolder.getContext().getAuthentication().getName()).orElseThrow();

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            return "Wrong password";
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        this.userRepository.saveAndFlush(user);

        return "Password changed";
    }

    public UserResponse changeUserAuthorityById(Long userId, String authority) {
        User user = this.userRepository.findById(userId).orElseThrow();
        user.setAuthority(authority);
        this.userRepository.saveAndFlush(user);
        return UserConverter.userToUserResponse(user);
    }

    public void checkLoginAttempts(String email) {
        Optional<User> userOptional = this.userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            int logInAttempts = 5;
            if (user.getLoginAttempts() < logInAttempts) {
                user.setLoginAttempts(user.getLoginAttempts() + 1);
            } else {
                user.setAutoLockedAt(LocalDateTime.now());
                user.setAccountNonLocked(false);
            }
            this.userRepository.saveAndFlush(user);
        }
    }

    public boolean isAutoAccountLockExpired(String email) {
        Optional<User> userOptional = this.userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            LocalDateTime timeLocked = user.getAutoLockedAt();
            long lockTime = 10;
            if (timeLocked != null && timeLocked.isBefore(LocalDateTime.now().minusMinutes(lockTime))) {
                user.setAutoLockedAt(null);
                user.setAccountNonLocked(true);
                user.setLoginAttempts(0);
                this.userRepository.saveAndFlush(user);
                return true;
            }
        }
        return false;
    }

    public Map<String, Object> getJwks() {
        return this.jwkSet.toJSONObject();
    }

    private String createRefreshToken(User user) {
        String token = UUID.randomUUID().toString();
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .expiresAt(Instant.now().plusMillis(18000000))
                .token(token)
                .build();
        this.refreshTokenRepository.saveAndFlush(refreshToken);

        return token;
    }
}
