package com.rk.security.config;

import com.rk.security.jwt.filter.JwtAuthenticationFilter;
import com.rk.security.jwt.utils.JwtAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
public class SecurityConfig {

    private final DataSource dataSource;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Bean
    public SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests (requests->
                        requests.requestMatchers ( "/h2-console/**" ).permitAll ()
                                .requestMatchers ( "/login" ).permitAll ()
                                .anyRequest().authenticated())
                .csrf (csrf->{
                    csrf.ignoringRequestMatchers ( "/h2-console/**" );
                    csrf.disable ();
                })
                .headers (headers->headers.frameOptions (frameOptionsConfig -> frameOptionsConfig.sameOrigin ()))
                .sessionManagement (session->session.sessionCreationPolicy ( SessionCreationPolicy.STATELESS ))
                .addFilterBefore ( jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class )
                .exceptionHandling (exception->exception.authenticationEntryPoint ( jwtAuthenticationEntryPoint ))
                //.httpBasic (withDefaults ())
                .build ();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails admin = User.withUsername ( "admin" ).password( passwordEncoder ().encode ( "admin" ) ).roles( "ADMIN").build();
        UserDetails user = User.withUsername ( "user" ).password( passwordEncoder ().encode ( "user" ) ).roles("USER").build();

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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder ();
    }

    @Bean
    public AuthenticationManager authenticationManager( AuthenticationConfiguration builder ) throws Exception {
        return builder.getAuthenticationManager ();
    }

}
