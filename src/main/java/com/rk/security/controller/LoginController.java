package com.rk.security.controller;

import com.rk.security.jwt.utils.JwtUtil;
import com.rk.security.model.LoginRequest;
import com.rk.security.model.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor (onConstructor_ = {@Autowired})
public class LoginController {
    private static final Logger logger= LoggerFactory.getLogger ( LoginController.class );

    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @PostMapping ("/auth/login")
    public ResponseEntity<Object> authenticateUser( @RequestBody LoginRequest loginRequest ) {
        Authentication authentication;
        try{
            authentication=authenticationManager.authenticate ( new UsernamePasswordAuthenticationToken (loginRequest.getUsername(), loginRequest.getPassword()) );
        } catch (AuthenticationException e) {
            final Map <String, Object> errorDetails = new HashMap <> ();
            errorDetails.put ( "status", HttpStatus.NOT_FOUND.value() );
            errorDetails.put ( "message", e.getMessage() );
            errorDetails.put("timestamp", System.currentTimeMillis());
            return ResponseEntity.status ( HttpStatus.NOT_FOUND ).body ( errorDetails );
        }
        SecurityContextHolder.getContext ().setAuthentication ( authentication );
        UserDetails userDetails= (UserDetails) authentication.getPrincipal ();
        String jwtToken= jwtUtil.generateJwtToken ( userDetails );
        List <String> roles=userDetails.getAuthorities ()
                .stream ().map ( GrantedAuthority::getAuthority )
                .toList ();

        LoginResponse response=LoginResponse.builder ()
                .token ( jwtToken )
                .username ( userDetails.getUsername () )
                .roles ( roles )
                .build ();
        return ResponseEntity.ok (response);
    }
}
