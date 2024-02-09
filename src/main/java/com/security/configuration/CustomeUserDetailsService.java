package com.security.configuration;

import com.security.model.DBUser;
import com.security.repository.DBUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class CustomeUserDetailsService implements UserDetailsService {

    @Autowired
    private DBUserRepository dbUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        DBUser user = dbUserRepository.findByUsername(username);

        return new User(user.getUsername(), user.getPassword(), getGrantedAuthority(user.getRole()));
    }

    private List<GrantedAuthority> getGrantedAuthority(String role) {
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));

        return authorities;
    }
}
