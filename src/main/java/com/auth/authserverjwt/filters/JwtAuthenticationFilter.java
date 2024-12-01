package com.auth.authserverjwt.filters;

import com.auth.authserverjwt.services.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.time.LocalDateTime;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger loggerFilter = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JWTService jwtService;
    private final UserDetailsService userDetailsService;
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) {
        try {
            final String authHeader = request.getHeader("Authorization");
            loggerFilter.debug("{} Authorization header: {}", LocalDateTime.now(), authHeader);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                loggerFilter.debug("{} No valid Authorization header found. Proceeding without authentication.", LocalDateTime.now());
                filterChain.doFilter(request, response);
                return;
            }

            final String jwt = authHeader.substring(7);
            loggerFilter.debug("{} Extracted JWT from Authorization header: {}", LocalDateTime.now(), jwt);

            final String userEmail = jwtService.extractUsername(jwt);
            loggerFilter.debug("{} Extracted username from JWT: {}", LocalDateTime.now(), userEmail);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                loggerFilter.debug("{} No authentication found in SecurityContext. Attempting to authenticate user:{}",
                        LocalDateTime.now(), userEmail);

                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                loggerFilter.debug("{} Loaded UserDetails for user: {}", LocalDateTime.now(), userEmail);

                if (jwtService.isTokenValid(jwt, userDetails)) {
                    loggerFilter.debug("{} JWT is valid for user: {}", LocalDateTime.now(), userEmail);

                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    loggerFilter.debug("{} Authentication set in SecurityContext for user: {}", LocalDateTime.now(), userEmail);
                } else {
                    loggerFilter.debug("{} JWT is invalid for user: {}", LocalDateTime.now(), userEmail);
                }
            }

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            loggerFilter.error("{} Exception occurred during auth filter processing: {}", LocalDateTime.now(), e.getMessage(), e);
            handlerExceptionResolver.resolveException(request, response, null, e);
        }
    }

}
