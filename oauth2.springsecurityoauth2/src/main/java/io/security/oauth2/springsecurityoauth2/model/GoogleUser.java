package io.security.oauth2.springsecurityoauth2.model;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class GoogleUser extends OAuth2ProviderUser{

    public GoogleUser(OAuth2User oAuth2USer, ClientRegistration clientRegistration){
        super(oAuth2USer.getAttributes(),oAuth2USer,clientRegistration);
    }

    @Override
    public String getId() {
        return (String) getAttributes().get("sub");
    }

    @Override
    public String getUsername() {
        return (String) getAttributes().get("sub");
    }

}
