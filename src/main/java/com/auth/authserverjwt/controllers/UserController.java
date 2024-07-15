package com.auth.authserverjwt.controllers;

import com.auth.authserverjwt.dto.*;
import com.auth.authserverjwt.services.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;

import java.util.List;

@RestController
@RequestMapping("api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@Valid @RequestBody RegistrationRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(userService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(@Valid @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(this.userService.authenticate(request));
    }

    @PostMapping("token/refresh")
    public ResponseEntity<RefreshResponse> refresh(@RequestBody TokenRefreshRequest request) {
        return ResponseEntity.ok(this.userService.refreshToken(request));
    }

    @PreAuthorize("hasAuthority('Admin')")
    @GetMapping
    public ResponseEntity<List<UserResponse>> getUsers(@RequestParam(value = "email", required = false) String email
            ) {
        return ResponseEntity.ok(this.userService.getUsers(email));
    }

    @PreAuthorize("hasAuthority('User')")
    @PatchMapping("/{userId}/password/change")
    public ResponseEntity<String> changePassword(@PathVariable Long userId,
                                                 @Valid @RequestBody PasswordChangeRequest request, WebRequest webRequest) {
        return ResponseEntity.ok(this.userService.changePassword(userId, request, webRequest));
    }

    @PreAuthorize("hasAuthority('Admin')")
    @PatchMapping("/{userId}/lock")
    public ResponseEntity<UserResponse> lockUserById(@PathVariable Long userId,
                                                     @RequestParam(value = "status") String status) {
        return ResponseEntity.ok(this.userService.changeUserExpiredStatusById(userId, status));
    }

//    @PreAuthorize("hasAuthority('Admin')")
//    @PatchMapping("/{userId}/unlock")
//    public ResponseEntity<UserResponse> unLockUserById(@PathVariable Long userId) {
//        return ResponseEntity.ok(this.userService.changeUserLockedStatusById(userId, true));
//    }

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
}
