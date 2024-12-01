package com.auth.authserverjwt.services;

import com.auth.authserverjwt.testutils.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JWTServiceTest {

    @InjectMocks
    private JWTService jwtService;

    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        this.userDetails = TestUtils.getTestUser();
    }

    @Test
    void testExtractUsernameSuccess() {
        String username = this.jwtService.extractUsername(this.jwtService.generateToken(userDetails));

        assertEquals(username, userDetails.getUsername());
    }

    @Test
    void testIsTokenValid() {
        assertTrue(jwtService.isTokenValid(this.jwtService.generateToken(userDetails), userDetails));
    }

    @Test
    void testGenerateTokenSuccess() {
        String token = jwtService.generateToken(userDetails);

        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

}
