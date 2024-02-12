package com.authentication.auth.features.authentication;

import com.authentication.auth.features.authentication.dao.request.SignUpRequest;
import com.authentication.auth.features.authentication.dao.request.SigninRequest;
import com.authentication.auth.features.authentication.dao.response.JwtAuthenticationResponse;

public interface AuthenticationService {
    JwtAuthenticationResponse signup(SignUpRequest request);

    JwtAuthenticationResponse signin(SigninRequest request);
}
