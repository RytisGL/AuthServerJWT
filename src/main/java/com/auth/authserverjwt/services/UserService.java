package com.auth.authserverjwt.services;

import com.auth.authserverjwt.converters.UserConverter;
import com.auth.authserverjwt.dto.*;
import com.auth.authserverjwt.entities.RefreshToken;
import com.auth.authserverjwt.entities.User;
import com.auth.authserverjwt.exceptions.UniqueDataException;
import com.auth.authserverjwt.repositories.RefreshTokenRepository;
import com.auth.authserverjwt.repositories.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.WebRequest;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthenticationResponse register(RegistrationRequest request) {
        if (this.userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new UniqueDataException(""); //Come back to check
        }
        User user = User.builder()
                .email(request.getEmail())
                .password(this.passwordEncoder.encode(request.getPassword()))
                .accountNonLocked(true)
                .enabled(true)
                .authority("Write")
                .build();
        userRepository.saveAndFlush(user);

        return createAuthResponse(user.getEmail(), user, false);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

        User user = this.userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new EntityNotFoundException(""));
        return createAuthResponse(user.getEmail(), user, true);
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

    public String createRefreshToken(String email) {
        String token = UUID.randomUUID().toString();

        RefreshToken refreshToken = RefreshToken.builder()
                .user(this.userRepository.findByEmail(email).orElseThrow())
                .expiresAt(Instant.now().plusMillis(18000000))
                .token(token)
                .build();

        this.refreshTokenRepository.saveAndFlush(refreshToken);

        return token;
    }

    public RefreshResponse refreshToken(TokenRefreshRequest request) {
        RefreshToken refreshToken = this.refreshTokenRepository.findByToken(request.getToken());

        if (refreshToken == null) {
            //Not found fix later
            throw new RuntimeException();
        }

        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            //Expired fix later
            this.refreshTokenRepository.delete(refreshToken);
            throw new RuntimeException();
        }

        return new RefreshResponse(this.jwtService.generateToken(refreshToken.getUser()));
    }

    private AuthenticationResponse createAuthResponse(String email, User user, boolean existingUser) {
        if (existingUser) {
            RefreshToken refreshToken = this.refreshTokenRepository.findByUser(user);
            if (refreshToken != null) {
                this.refreshTokenRepository.delete(refreshToken);
            }
        }
        return new AuthenticationResponse(jwtService.generateToken(user), this.createRefreshToken(email));
    }

    public UserResponse changeUserLockedStatusById(Long userId, boolean locked) {
        User user = this.userRepository.findById(userId).orElseThrow();
        user.setAccountNonLocked(locked);
        this.userRepository.saveAndFlush(user);
        return UserConverter.userToUserResponse(user);
    }

    public String changePassword(Long userId, PasswordChangeRequest request, WebRequest webRequest) {
        User user = this.userRepository.findById(userId).orElseThrow();
        String tokenEmail = this.jwtService.extractUsername(Objects
                .requireNonNull(webRequest
                        .getHeader("Authorization")).substring(7));

        validateUser(user, tokenEmail);

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            return "Wrong password";
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        this.userRepository.saveAndFlush(user);

        return "Password changed";
    }

    private void validateUser(User user, String tokenEmail) {
        if (!user.getEmail().equals(tokenEmail)) {
            throw new RuntimeException();
        }
    }
}
