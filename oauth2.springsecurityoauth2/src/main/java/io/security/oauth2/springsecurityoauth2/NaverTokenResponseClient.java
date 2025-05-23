package io.security.oauth2.springsecurityoauth2;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

public class NaverTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> delegate =
            new DefaultAuthorizationCodeTokenResponseClient();

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest request) {
        String registrationId = request.getClientRegistration().getRegistrationId();

        if (!"naver".equals(registrationId)) {
            // 기본 provider 처리 (Google, Keycloak 등)
            return delegate.getTokenResponse(request);
        }

        // 네이버 전용 처리
        RequestEntity<?> req = createNaverRequest(request);
        ResponseEntity<Map<String, Object>> response = new RestTemplate()
                .exchange(req, new ParameterizedTypeReference<>() {});
        Map<String, Object> body = response.getBody();

        if (body == null || body.get("access_token") == null) {
            throw new IllegalStateException("Invalid token response from Naver: " + body);
        }

        // expires_in 이 int 로 올 수 있음 → long 으로 파싱
        long expiresIn = 0;
        Object expiresRaw = body.get("expires_in");
        if (expiresRaw instanceof String) {
            expiresIn = Long.parseLong((String) expiresRaw);
        } else if (expiresRaw instanceof Integer) {
            expiresIn = ((Integer) expiresRaw).longValue();
        }

        // scope 설정
        Set<String> scopes = Collections.singleton("openid"); // 실제로는 등록된 scope에 맞춰 동적 처리 가능

        // OIDC 조건 체크: openid scope + id_token 포함
        boolean isOidc = request.getClientRegistration().getScopes().contains("openid")
                && body.containsKey("id_token");

        // 추가 정보 매핑
        Map<String, Object> additionalParameters = new HashMap<>();
        if (body.containsKey("id_token") && isOidc) {
            additionalParameters.put("id_token", body.get("id_token"));
        }

        if (body.containsKey("refresh_token")) {
            additionalParameters.put("refresh_token", body.get("refresh_token"));
        }

        if(isOidc){
            return OAuth2AccessTokenResponse.withToken((String) body.get("access_token"))
                    .tokenType(OAuth2AccessToken.TokenType.BEARER)
                    .expiresIn(expiresIn)
                    .scopes(Set.of("openid"))
                    .refreshToken((String) body.get("refresh_token"))
                    .additionalParameters(additionalParameters)
                    .build();


        }
        return OAuth2AccessTokenResponse.withToken((String) body.get("access_token"))
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(expiresIn)
                .scopes(Set.of("profile","email"))
                .refreshToken((String) body.get("refresh_token"))
                .additionalParameters(additionalParameters)
                .build();


    }

    private RequestEntity<?> createNaverRequest(OAuth2AuthorizationCodeGrantRequest request) {
        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.add("grant_type", "authorization_code");
        formParams.add("code", request.getAuthorizationExchange().getAuthorizationResponse().getCode());
        formParams.add("client_id", request.getClientRegistration().getClientId());
        formParams.add("client_secret", request.getClientRegistration().getClientSecret());
        formParams.add("redirect_uri", request.getAuthorizationExchange().getAuthorizationRequest().getRedirectUri());

        return RequestEntity
                .post(URI.create(request.getClientRegistration().getProviderDetails().getTokenUri()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(formParams);
    }
}
