package com.example.ssl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

@Controller
class PageController {

    @GetMapping("/")
    public String index() {
        return "forward:/index.html";
    }
}

@RestController
public class HelloController {

    @Value("${casdoor.base-url}")
    private String casdoorBaseUrl;

    @Value("${casdoor.client-id}")
    private String clientId;

    @Value("${casdoor.client-secret}")
    private String clientSecret;

    @Value("${casdoor.redirect-uri}")
    private String redirectUri;

    @Value("${casdoor.scope}")
    private String scope;

    @Value("${casdoor.jwks-uri}")
    private String jwksUri;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SecureRandom secureRandom = new SecureRandom();

    @GetMapping("/login")
    public void login(HttpServletResponse response) throws IOException {
        String state = generateRandomValue();
        String nonce = generateRandomValue();

        addCookie(response, "oidc_state", state, 300, true);
        addCookie(response, "oidc_nonce", nonce, 300, true);

        String authorizationUrl = casdoorBaseUrl + "/login/oauth/authorize"
                + "?client_id=" + encode(clientId)
                + "&response_type=code"
                + "&redirect_uri=" + encode(redirectUri)
                + "&scope=" + encode(scope)
                + "&state=" + encode(state)
                + "&nonce=" + encode(nonce);

        response.sendRedirect(authorizationUrl);
    }

    @GetMapping("/callback")
    public void callback(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String code = request.getParameter("code");
        String returnedState = request.getParameter("state");
        String savedState = getCookieValue(request, "oidc_state");

        if (code == null || code.isBlank()) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Authorization code is missing");
            return;
        }

        if (returnedState == null || savedState == null || !returnedState.equals(savedState)) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid state parameter");
            return;
        }

        String tokenResponse = exchangeCodeForToken(code);
        JsonNode tokenJson = objectMapper.readTree(tokenResponse);

        if (!tokenJson.has("access_token")) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Access token was not received");
            return;
        }

        String accessToken = tokenJson.get("access_token").asText();

        addCookie(response, "access_token", accessToken, 3600, false);

        response.sendRedirect("/");
    }

    @GetMapping("/user-info")
    public ResponseEntity<?> userInfo(HttpServletRequest request) {
        String accessToken = getCookieValue(request, "access_token");

        if (accessToken == null || accessToken.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Missing access token");
        }

        try {
            JsonNode claims = validateJwtAndGetClaims(accessToken);
            return ResponseEntity.ok(claims);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid JWT token: " + e.getMessage());
        }
    }

    private JsonNode validateJwtAndGetClaims(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");

        if (parts.length != 3) {
            throw new RuntimeException("JWT must contain header, payload and signature");
        }

        String headerJson = new String(
                Base64.getUrlDecoder().decode(parts[0]),
                StandardCharsets.UTF_8
        );

        String payloadJson = new String(
                Base64.getUrlDecoder().decode(parts[1]),
                StandardCharsets.UTF_8
        );

        JsonNode header = objectMapper.readTree(headerJson);
        JsonNode claims = objectMapper.readTree(payloadJson);

        String alg = header.has("alg") ? header.get("alg").asText() : "";
        if (!"RS256".equals(alg)) {
            throw new RuntimeException("Unsupported JWT algorithm: " + alg);
        }

        String kid = header.has("kid") ? header.get("kid").asText() : null;
        if (kid == null || kid.isBlank()) {
            throw new RuntimeException("JWT header does not contain kid");
        }

        PublicKey publicKey = getPublicKeyFromJwks(kid);

        String signedData = parts[0] + "." + parts[1];
        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(signedData.getBytes(StandardCharsets.UTF_8));

        boolean validSignature = signature.verify(signatureBytes);
        if (!validSignature) {
            throw new RuntimeException("Invalid JWT signature");
        }

        validateJwtClaims(claims);

        return claims;
    }

    private PublicKey getPublicKeyFromJwks(String kid) throws Exception {
        HttpRequest jwksRequest = HttpRequest.newBuilder()
                .uri(URI.create(jwksUri))
                .GET()
                .build();

        HttpResponse<String> jwksResponse =
                httpClient.send(jwksRequest, HttpResponse.BodyHandlers.ofString());

        if (jwksResponse.statusCode() != 200) {
            throw new RuntimeException("Cannot load JWKS");
        }

        JsonNode jwks = objectMapper.readTree(jwksResponse.body());
        JsonNode keys = jwks.get("keys");

        if (keys == null || !keys.isArray()) {
            throw new RuntimeException("JWKS does not contain keys");
        }

        for (JsonNode key : keys) {
            String keyId = key.has("kid") ? key.get("kid").asText() : "";

            if (kid.equals(keyId)) {
                String n = key.get("n").asText();
                String e = key.get("e").asText();

                byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
                byte[] exponentBytes = Base64.getUrlDecoder().decode(e);

                BigInteger modulus = new BigInteger(1, modulusBytes);
                BigInteger exponent = new BigInteger(1, exponentBytes);

                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                return keyFactory.generatePublic(keySpec);
            }
        }

        throw new RuntimeException("Public key with kid was not found");
    }

    private void validateJwtClaims(JsonNode claims) {
        long now = System.currentTimeMillis() / 1000;

        if (!claims.has("exp")) {
            throw new RuntimeException("JWT does not contain exp");
        }

        long exp = claims.get("exp").asLong();
        if (exp < now) {
            throw new RuntimeException("JWT has expired");
        }

        if (claims.has("nbf")) {
            long nbf = claims.get("nbf").asLong();
            if (nbf > now) {
                throw new RuntimeException("JWT is not active yet");
            }
        }

        if (!claims.has("iss")) {
            throw new RuntimeException("JWT does not contain iss");
        }

        String issuer = claims.get("iss").asText();

        if (!issuer.equals(casdoorBaseUrl)) {
            throw new RuntimeException("Invalid issuer");
        }

        if (!claims.has("aud")) {
            throw new RuntimeException("JWT does not contain aud");
        }

        JsonNode aud = claims.get("aud");
        boolean validAudience = false;

        if (aud.isTextual()) {
            validAudience = clientId.equals(aud.asText());
        } else if (aud.isArray()) {
            for (JsonNode item : aud) {
                if (clientId.equals(item.asText())) {
                    validAudience = true;
                    break;
                }
            }
        }

        if (!validAudience) {
            throw new RuntimeException("Invalid audience");
        }
    }

    private String exchangeCodeForToken(String code) throws Exception {
        String body = "grant_type=authorization_code"
                + "&client_id=" + encode(clientId)
                + "&client_secret=" + encode(clientSecret)
                + "&code=" + encode(code)
                + "&redirect_uri=" + encode(redirectUri);

        HttpRequest tokenRequest = HttpRequest.newBuilder()
                .uri(URI.create(casdoorBaseUrl + "/api/login/oauth/access_token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> tokenResponse =
                httpClient.send(tokenRequest, HttpResponse.BodyHandlers.ofString());

        if (tokenResponse.statusCode() != 200) {
            throw new RuntimeException("Token endpoint returned status: " + tokenResponse.statusCode());
        }

        return tokenResponse.body();
    }

    private void addCookie(HttpServletResponse response,
                           String name,
                           String value,
                           int maxAge,
                           boolean httpOnly) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setHttpOnly(httpOnly);
        cookie.setSecure(true);
        response.addCookie(cookie);
    }

    private String getCookieValue(HttpServletRequest request, String name) {
        if (request.getCookies() == null) {
            return null;
        }

        for (Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }

    private String generateRandomValue() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}