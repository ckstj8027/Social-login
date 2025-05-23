package io.security.oauth2.springsecurityoauth2.service;

import io.security.oauth2.springsecurityoauth2.model.GoogleUser;
import io.security.oauth2.springsecurityoauth2.model.KeyCloakUser;
import io.security.oauth2.springsecurityoauth2.model.NaverUser;
import io.security.oauth2.springsecurityoauth2.model.OAuth2ProviderUser;
import io.security.oauth2.springsecurityoauth2.model.User;
import io.security.oauth2.springsecurityoauth2.repository.UserRepository;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Getter
@Service
public class AbstractOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    public void register(OAuth2ProviderUser providerUser, OAuth2UserRequest userRequest) {

        User user = userRepository.findByUsername(providerUser.getUsername());

        if(user==null){
            String registrationId = userRequest.getClientRegistration().getRegistrationId();
            userService.register(registrationId ,providerUser);
        }else {

            System.out.println("user = " + user);
        }


    }





    public OAuth2ProviderUser providerUser(ClientRegistration clientRegistration, OAuth2User oAuth2User) {

        String registrationId = clientRegistration.getRegistrationId();
        if(registrationId.equals("keycloak")){

            return new KeyCloakUser(oAuth2User,clientRegistration);

        }
        else if(registrationId.equals("google")){
            return new GoogleUser(oAuth2User,clientRegistration);

        }
        else if(registrationId.equals("naver")){

            return new NaverUser(oAuth2User,clientRegistration);
        }

        return null;
    }


}
