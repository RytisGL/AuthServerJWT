package com.auth.authserverjwt.dto;

import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PasswordChangeRequest {
    private String oldPassword;
    @Pattern(regexp = "^(?!.* )(?=.*\\d)(?=.*[A-Z]).{8,20}$", message = "Password must be 8 - 20 symbols long and " +
            "must contain uppercase letters")
    private String newPassword;
}
