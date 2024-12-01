package com.auth.authserverjwt.configs;

import com.auth.authserverjwt.filters.JwtAuthenticationFilter;
import com.auth.authserverjwt.utils.KeyUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

            http.cors(corsCustomizer -> corsCustomizer.configurationSource(corsConfigurationSource()))
                    //HTTPS traffic only
//                    .requiresChannel(rcc -> rcc.anyRequest().requiresSecure())
                    //Csrf protection not needed
                .csrf(AbstractHttpConfigurer::disable)
                    //Disable http basic login
                    .httpBasic(AbstractHttpConfigurer::disable)
                    //Disable login form
                    .formLogin(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeHttpRequests ->
                        authorizeHttpRequests
                                .requestMatchers("/v3/**", "/swagger-ui/**").permitAll()
                                .requestMatchers("api/v1/user/oauth2/jwks").permitAll()
                                .requestMatchers("api/v1/user/register").anonymous()
                                .requestMatchers("api/v1/user/login").anonymous()
                                .requestMatchers("api/v1/user/logout").anonymous()
                                .requestMatchers("api/v1/user/token/refresh").anonymous()
                                .anyRequest().authenticated()
                ).sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                ).authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(List.of(System.getenv("ALLOWED_ORIGINS")));
        configuration.setAllowedMethods(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setExposedHeaders(List.of("*"));
        configuration.setExposedHeaders(List.of("Authorisation"));
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public KeyPair keyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public JWKSet jwkSet() {
        RSAPrivateKey privateKey = (RSAPrivateKey) KeyUtils.getSignInKey();
        RSAPublicKey publicKey = (RSAPublicKey) KeyUtils.getPublicKeyFromPrivateKey(privateKey);

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("1")
                .build();
        return new JWKSet(rsaKey);
    }
}
