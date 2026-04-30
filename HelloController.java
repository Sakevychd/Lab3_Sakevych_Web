package com.example.ssl;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/home")
    public String home() {
        return "OIDC Spring Boot app is running";
    }

    @GetMapping("/login")
    public String login() {
        return "redirect:/oauth2/authorization/casdoor";
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(@AuthenticationPrincipal OidcUser user) {
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Not logged in");
        }

        return ResponseEntity.ok(user.getClaims());
    }

    @GetMapping("/user-info")
    public ResponseEntity<?> userInfo(@AuthenticationPrincipal OidcUser user) {
        if (user == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        return ResponseEntity.ok(user.getClaims());
    }

    @GetMapping("/token")
    public ResponseEntity<?> token(
            OAuth2AuthenticationToken authentication,
            @RegisteredOAuth2AuthorizedClient("casdoor") OAuth2AuthorizedClient authorizedClient
    ) {
        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token not found");
        }

        return ResponseEntity.ok(authorizedClient.getAccessToken().getTokenValue());
    }

    @GetMapping("/user-info-token")
    public ResponseEntity<?> userInfoWithToken(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Missing or invalid Authorization header");
        }

        String token = authHeader.replace("Bearer ", "");

        return ResponseEntity.ok("Token received: " + token);
    }
}