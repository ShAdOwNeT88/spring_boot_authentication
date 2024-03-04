package com.authentication.auth.features.authentication.dao.repositories;

import com.authentication.auth.features.authentication.dao.entities.RefreshToken;
import com.authentication.auth.features.user.entities.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends CrudRepository<RefreshToken, Integer> {
    Optional<RefreshToken> findByToken(String token);
    List<RefreshToken> findByUserInfo(User user);
}
