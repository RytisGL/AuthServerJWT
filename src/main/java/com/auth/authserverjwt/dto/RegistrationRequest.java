package com.auth.authserverjwt.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegistrationRequest {
    @NotBlank(message = "Email cannot be blank")
    @Size(min = 5, max = 50, message = "Email must be between {min} and {max} symbols long")
    @Email(message = "Email is not valid")
    private String email;
    @Pattern(regexp = "^(?!.* )(?=.*\\d)(?=.*[A-Z]).{8,20}$", message = "Password must be 8 - 20 symbols long and " +
            "must contain uppercase letter")
    private String password;
}
