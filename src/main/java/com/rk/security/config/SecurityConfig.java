package com.rk.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class SecurityConfig {

    private final DataSource dataSource;

    @Bean
    public SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests (requests->
                        requests.requestMatchers ( "/h2-console/**" ).permitAll ()
                                .anyRequest().authenticated())
                .csrf (csrf->csrf.ignoringRequestMatchers ( "/h2-console/**" ))
                .headers (headers->headers.frameOptions (frameOptionsConfig -> frameOptionsConfig.sameOrigin ()))
                .sessionManagement (session->session.sessionCreationPolicy ( SessionCreationPolicy.STATELESS ))
                .httpBasic (withDefaults())
                .build ();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails admin = User.withUsername ( "admin" ).password( "{noop}admin" ).roles( "ADMIN").build();
        UserDetails user = User.withUsername ( "user" ).password( "{noop}user" ).roles("USER").build();

        JdbcUserDetailsManager userDetailsManager=new JdbcUserDetailsManager ( dataSource );
        userDetailsManager.createUser ( admin );
        userDetailsManager.createUser ( user );
        return userDetailsManager;
        //return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.withDefaultRolePrefix ().role ( "ADMIN" ).implies ( "USER" ).build ();
    }

}
