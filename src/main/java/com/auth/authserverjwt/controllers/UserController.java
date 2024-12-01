package com.auth.authserverjwt.controllers;

import com.auth.authserverjwt.dto.*;
import com.auth.authserverjwt.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("api/v1/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegistrationRequest request, HttpServletResponse response) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.register(request, response));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(@Valid @RequestBody AuthenticationRequest request, HttpServletResponse response) {
        return ResponseEntity.ok(this.userService.authenticate(request, response));
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletResponse response) {
        return ResponseEntity.ok(userService.logout(response));
    }

    @PostMapping("token/refresh")
    public ResponseEntity<AuthenticationResponse> refresh(HttpServletRequest request) {
        return ResponseEntity.ok(this.userService.refreshToken(request));
    }

    @PreAuthorize("hasAuthority('Admin')")
    @GetMapping
    public ResponseEntity<List<UserResponse>> getUsers(@RequestParam(value = "email", required = false) String email) {
        return ResponseEntity.ok(this.userService.getUsers(email));
    }

    @PutMapping("/password/change")
    public ResponseEntity<String> changePassword(@Valid @RequestBody PasswordChangeRequest request) {
        return ResponseEntity.ok(this.userService.changePassword(request));
    }

    @PreAuthorize("hasAuthority('Admin')")
    @PatchMapping("/{userId}/lock")
    public ResponseEntity<UserResponse> changeExpiredStatusById(@PathVariable Long userId,
                                                     @RequestParam(value = "status") String status) {
        return ResponseEntity.ok(this.userService.changeExpiredStatusById(userId, status));
    }

    @PreAuthorize("hasAuthority('Admin')")
    @PatchMapping("/{userId}/authority")
    public ResponseEntity<UserResponse> changeUserAuthority(@PathVariable Long userId, String authority) {
        return ResponseEntity.ok(this.userService.changeUserAuthorityById(userId, authority));
    }

    @PreAuthorize("hasAuthority('Admin')")
    @DeleteMapping("/{userId}")
    public ResponseEntity<UserResponse> deleteUserById(@PathVariable Long userId) {
        return ResponseEntity.ok(this.userService.deleteUserById(userId));
    }

    //Oauth2 details for resource server
    @GetMapping("/oauth2/jwks")
    public ResponseEntity<Map<String, Object>> getJwks() {
        return ResponseEntity.ok(this.userService.getJwks());
    }
}
