package com.auth.authserverjwt.services;

import com.auth.authserverjwt.utils.KeyUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JWTService {

    private static final Logger logger = LoggerFactory.getLogger(JWTService.class);

    public String extractUsername(String token) {
        logger.debug("{} Extracting username from token: {}", LocalDateTime.now(), token);
        String username = extractClaim(token, Claims::getSubject);
        logger.debug("{} Extracted username: {}", LocalDateTime.now(), username);
        return username;
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        logger.debug("{} Validating token for user: {}", LocalDateTime.now(), userDetails.getUsername());
        final String username = extractUsername(token);
        boolean isValid = username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        logger.debug("{} Token validation result: {}, for user: {}", LocalDateTime.now(), isValid, userDetails.getUsername());
        return isValid;
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        logger.debug("{} Extracting claims from token", LocalDateTime.now());
        final Claims claims = extractClaims(token);
        T claim = claimsResolver.apply(claims);
        logger.debug("{} Extracted claim: {}", LocalDateTime.now(), claim);
        return claim;
    }

    public String generateToken(UserDetails userDetails) {
        logger.debug("{} Generating token for user: {}", LocalDateTime.now(), userDetails.getUsername());
        String token = generateToken(new HashMap<>(), userDetails);
        logger.debug("{} Generated token for user: {}", LocalDateTime.now(), userDetails.getUsername());
        return token;
    }

    private boolean isTokenExpired(String token) {
        logger.debug("{} Checking if token is expired", LocalDateTime.now());
        boolean expired = extractExpiration(token).before(new Date());
        logger.debug("{} Token expired: {}", LocalDateTime.now(), expired);
        return expired;
    }

    private Date extractExpiration(String token) {
        logger.debug("{} Extracting expiration date from token", LocalDateTime.now());
        Date expirationDate = extractClaim(token, Claims::getExpiration);
        logger.debug("{} Token expiration date: {}", LocalDateTime.now(), expirationDate);
        return expirationDate;
    }

    private String generateToken(Map<String, Object> claims, UserDetails userDetails) {
        logger.debug("{} Generating token with custom claims for user: {}", LocalDateTime.now(), userDetails.getUsername());

        List<String> authorities = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        claims.put("authorities", authorities);

        Date expirationDate = new Date(System.currentTimeMillis() + Long.parseLong(System.getenv("JWT_EXPIRATION")));
        logger.debug("{} Token expiration set to: {}", LocalDateTime.now(), expirationDate);

        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(expirationDate)
                .signWith(KeyUtils.getSignInKey(), SignatureAlgorithm.RS256)
                .compact();

        logger.debug("{} Token successfully generated for user: {}", LocalDateTime.now(), userDetails.getUsername());
        return token;
    }

    private Claims extractClaims(String token) {
        logger.debug("{} Parsing claims from token", LocalDateTime.now());
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(KeyUtils.getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        logger.debug("{} Parsed claims: {}", LocalDateTime.now(), claims);
        return claims;
    }

}
