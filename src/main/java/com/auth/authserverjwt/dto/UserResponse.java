package com.auth.authserverjwt.dto;

import lombok.Data;

import java.sql.Date;
import java.time.LocalDateTime;

@Data
public class UserResponse {
    private Long id;
    private String email;
    private String authority;
    private boolean accountNonLocked;
    private boolean enabled;
    private boolean manuallyNonLocked;
    private int loginAttempts;
    private Date autoLockedAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
