package com.authentication.auth.features.authentication;

import com.authentication.auth.features.authentication.dto.request.RefreshTokenRequest;
import com.authentication.auth.features.authentication.dto.request.SignUpRequest;
import com.authentication.auth.features.authentication.dto.request.SigninRequest;
import com.authentication.auth.features.authentication.dto.response.JwtAuthenticationResponse;

public interface AuthenticationService {
    JwtAuthenticationResponse signup(SignUpRequest request);

    JwtAuthenticationResponse signin(SigninRequest request);

    JwtAuthenticationResponse refreshToken(RefreshTokenRequest request);
}
