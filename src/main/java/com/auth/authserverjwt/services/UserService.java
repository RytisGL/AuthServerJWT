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
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.WebRequest;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
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
                .authority("Write")
                .build();
        userRepository.saveAndFlush(user);

        return createAuthResponse(user.getEmail(), user, false);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request, HttpServletRequest httpRequest) {
        //Future work bellow
        httpRequest.getRemoteUser(); // <---- check ip against db
        try {
            this.authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        } catch (BadCredentialsException e) {
            checkLoginAttempts(request.getEmail());
            throw e;
        } catch (LockedException ex) {
            if (isAutoAccountLockExpired(request.getEmail())) {
                authenticate(request, httpRequest);
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
            throw new BadCredentialsException("Bad credentials");
        }

        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            this.refreshTokenRepository.delete(refreshToken);
            throw new RefreshTknExpireException();
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

    public UserResponse changeUserExpiredStatusById(Long userId, String status) {
        User user = this.userRepository.findById(userId).orElseThrow();

        if (!status.equals("true") && !status.equals("false")) {
            throw new BadRequestException();
        }

        user.setAccountNonExpired(!status.equals("true"));

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

    public UserResponse changeUserAuthorityById(Long userId, String authority) {
        User user = this.userRepository.findById(userId).orElseThrow();
        user.setAuthority(authority);
        return UserConverter.userToUserResponse(user);
    }

    private void validateUser(User user, String tokenEmail) {
        if (!user.getEmail().equals(tokenEmail)) {
            throw new AccessDeniedException("Access denied");
        }
    }

    private void checkLoginAttempts(String email) {
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
}
