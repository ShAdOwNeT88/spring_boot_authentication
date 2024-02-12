package com.authentication.auth.features.resources;

import com.authentication.auth.features.user.entities.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/resource")
@RequiredArgsConstructor
public class AuthorizationController {
    @GetMapping
    public ResponseEntity<String> sayHello(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok("Here is your resource with the user: " + user);
    }
}
