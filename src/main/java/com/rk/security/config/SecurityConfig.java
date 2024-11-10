package com.rk.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests (requests->requests.anyRequest().authenticated())
                .sessionManagement (session->session.sessionCreationPolicy ( SessionCreationPolicy.STATELESS ))
                .httpBasic (withDefaults())
                .build ();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails admin = User.withUsername ( "admin" ).password( "{noop}admin" ).roles("USER", "ADMIN").build();
        UserDetails user = User.withUsername ( "user" ).password( "{noop}user" ).roles("USER").build();
        return new InMemoryUserDetailsManager(user, admin);
    }

}
