package com.auth.authserverjwt.repositories;

import com.auth.authserverjwt.entities.RefreshToken;
import com.auth.authserverjwt.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    RefreshToken findByToken(String token);
    RefreshToken findByUser(User user);
}