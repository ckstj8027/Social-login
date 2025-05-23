package io.security.oauth2.springsecurityoauth2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import org.springframework.web.client.RestTemplate;

@Controller
public class IndexController {

    @Autowired
    private  OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/")
    public String index(Model model, Authentication authentication,  @AuthenticationPrincipal OAuth2User oAuth2User){

        OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
        if(oAuth2AuthenticationToken!=null){
            Map<String, Object> attributes = oAuth2User.getAttributes();
            String name = (String) attributes.get("name");

            if(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId().equals("naver")){


                if((Map<String, Object>) attributes.get("response") != null ){
                    Map<String, Object> response = (Map<String, Object>) attributes.get("response");
                    name= (String) response.get("name");
                }
                else {
                    OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
                            oAuth2AuthenticationToken.getAuthorizedClientRegistrationId(),
                            oAuth2AuthenticationToken.getName()
                    );


                    String url = "https://openapi.naver.com/v1/nid/me";

                    HttpHeaders headers = new HttpHeaders();
                    headers.set("Authorization", "Bearer " + client.getAccessToken().getTokenValue());
                    HttpEntity<String> entity = new HttpEntity<>(headers);

                    RestTemplate restTemplate = new RestTemplate();
                    ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, entity, Map.class);

                    Map<String, Object> userInfo = response.getBody();

                    Map<String, Object> temp = (Map<String, Object>) userInfo.get("response");

                    name = (String) temp.get("name");
                    String email = (String)temp.get("email");
                    System.out.println("email = " + email);
                }


            }

            model.addAttribute("user",name);

        }









        return "index";
    }

}
