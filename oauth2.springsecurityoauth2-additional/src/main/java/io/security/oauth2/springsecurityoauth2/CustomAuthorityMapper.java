package io.security.oauth2.springsecurityoauth2;

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

public class CustomAuthorityMapper implements GrantedAuthoritiesMapper {

    private String prefix="ROLE_";



    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {

        HashSet<GrantedAuthority> mapped = new HashSet(authorities.size());
        Iterator var3 = authorities.iterator();

        while(var3.hasNext()) {
            GrantedAuthority authority = (GrantedAuthority)var3.next();
            mapped.add(this.mapAuthority(authority.getAuthority()));
        }


        return mapped;

    }

    private GrantedAuthority mapAuthority(String name) { // http://google.com/asdf/asdf/email
        if (name.lastIndexOf(".")>0) {
            int index = name.lastIndexOf(".");
            name = "SCOPE_" + name.substring(index + 1);
        }
        if(prefix.length()>0 && !name.startsWith(prefix)){
            name =prefix+name;
        }




        return new SimpleGrantedAuthority(name);
    }
}
