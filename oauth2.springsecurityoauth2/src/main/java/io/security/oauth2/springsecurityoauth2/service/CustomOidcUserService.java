package io.security.oauth2.springsecurityoauth2.service;

import io.security.oauth2.springsecurityoauth2.model.OAuth2ProviderUser;
import java.util.Map;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class CustomOidcUserService extends  AbstractOAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {
    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        ClientRegistration clientRegistration = userRequest.getClientRegistration();

        // 기본 OidcUserService 사용
        OidcUserService oidcUserService = new OidcUserService();
        OidcUser oidcUser = oidcUserService.loadUser(userRequest);

        // 네이버의 경우, response 내에 id가 있기 때문에 이를 sub로 매핑
        Map<String, Object> claims = oidcUser.getAttributes();

        if (claims.containsKey("response")) {
            Map<String, Object> response = (Map<String, Object>) claims.get("response");
            if (response.containsKey("id")) {
                // 네이버의 'id'를 'sub'로 변환하여 설정
                claims.put("sub", response.get("id"));
            }
        }

        // 클레임에서 'sub'을 가져와서 네이버 응답에 맞는 사용자 처리
        if (claims.get("sub") == null) {
            OAuth2AuthenticationException exception = new OAuth2AuthenticationException("No subject found in the user info response");
            throw exception;
        }

        // OAuth2ProviderUser 생성
        OAuth2ProviderUser providerUser = super.providerUser(clientRegistration, oidcUser);

        // 회원가입 또는 추가 처리
        super.register(providerUser, userRequest);

        return oidcUser;


    }



}
