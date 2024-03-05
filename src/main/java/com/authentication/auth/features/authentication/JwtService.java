package com.authentication.auth.features.authentication;

import com.authentication.auth.features.authentication.entities.RefreshToken;
import com.authentication.auth.features.user.entities.User;
import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {
    String extractUserName(String token);

    String generateToken(UserDetails userDetails);

    RefreshToken generateRefreshToken(User user);

    boolean isRefreshTokenExpired(RefreshToken token);

    boolean isTokenValid(String token, UserDetails userDetails);
}
