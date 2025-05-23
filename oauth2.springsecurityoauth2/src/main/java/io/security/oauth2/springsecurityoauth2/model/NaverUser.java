package io.security.oauth2.springsecurityoauth2.model;

import java.util.Map;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class NaverUser extends OAuth2ProviderUser{

    public NaverUser(OAuth2User oAuth2User, ClientRegistration clientRegistration){


   //     super((Map<String, Object>)oAuth2User.getAttributes().get("response") ,oAuth2User,clientRegistration);
        super((Map<String, Object>) oAuth2User.getAttributes().get("response") != null ? (Map<String, Object>) oAuth2User.getAttributes().get("response") : (Map<String, Object>) oAuth2User.getAttributes() ,oAuth2User,clientRegistration);

     //   super((Map<String, Object>) oAuth2USer.getAttributes(),oAuth2USer,clientRegistration);
    }

    @Override
    public String getId() {
       return (String) getAttributes().get("id");

    }

    @Override
    public String getUsername() {
       return (String) getAttributes().get("email");

    }
}
