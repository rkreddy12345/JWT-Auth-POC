package com.rk.security.jwt.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public void commence ( HttpServletRequest request, HttpServletResponse response, AuthenticationException authException ) throws IOException, ServletException {
        response.setStatus( HttpServletResponse.SC_UNAUTHORIZED );
        response.setContentType (MediaType.APPLICATION_JSON_VALUE);

        final Map <String, Object> errorDetails = new HashMap <> ();
        errorDetails.put ( "status", HttpServletResponse.SC_UNAUTHORIZED );
        errorDetails.put("path", request.getServletPath());
        errorDetails.put ( "message", "Unauthorized: "+authException.getMessage() );
        errorDetails.put("timestamp", System.currentTimeMillis());

        mapper.writeValue(response.getOutputStream (), errorDetails );

    }
}
