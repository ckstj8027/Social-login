package io.security.oauth2.springsecurityoauth2.model;

import java.util.List;
import java.util.Map;

import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;


public interface ProviderUser {


    String getId() ;
    String getUsername();
    String getPassword();
    String getEmail();
    String getProvider();
    List<? extends GrantedAuthority> getAuthorities();

    Map<String , Object> getAttributes();




}
