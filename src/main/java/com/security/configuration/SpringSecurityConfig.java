package com.security.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {

    @Autowired
    private CustomeUserDetailsService customeUserDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

        return httpSecurity.authorizeHttpRequests(auth -> {
            auth.requestMatchers("/admin").hasRole("ADMIN");
            auth.requestMatchers("/user").hasRole("USER");

            auth.anyRequest().authenticated();
        }).formLogin(Customizer.withDefaults()).build();
    }

    @Bean
    public UserDetailsService users() {
        // Utilisateur in memory
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("user"))
                .roles("USER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN", "USER")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        // encodeur de mot de passe
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity httpSecurity, BCryptPasswordEncoder bCryptPasswordEncoder) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder = httpSecurity
                .getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder.userDetailsService(customeUserDetailsService)
                .passwordEncoder(bCryptPasswordEncoder);

        return authenticationManagerBuilder.build();
    }
}
