package com.rk.security.jwt.filter;

import com.rk.security.jwt.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;

@Component
@RequiredArgsConstructor(onConstructor_ = {@Autowired})
@NoArgsConstructor ( force = true )
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    /**
     * Circular Dependency Issue<br>
     * <br>
     * The application encountered a startup failure due to a circular dependency in the Spring Bean creation process.<br>
     * The detected cycle involved:<br>
     * <br>
     * - JwtAuthenticationFilter: Defined in the filter package.<br>
     * - SecurityConfig: Defined in the configuration package.<br>
     * <br>
     * Reason for the Circular Dependency:<br>
     * - JwtAuthenticationFilter depends on a bean managed by SecurityConfig.<br>
     * - SecurityConfig indirectly depends on JwtAuthenticationFilter, creating a cycle.<br>
     * <br>
     * Logs:<br>
     * Error creating bean with name 'jwtAuthenticationFilter':<br>
     * Requested bean is currently in creation: Is there an unresolvable circular reference?<br>
     * <br>
     * Resolution:<br>
     * To resolve this issue, ObjectProvider was used in the JwtAuthenticationFilter.<br>
     * This allows lazy injection of UserDetailsService or other dependencies, breaking the circular reference.<br>
     */
    private final ObjectProvider <UserDetailsService> userDetailsServiceProvider;

    @Override
    protected void doFilterInternal ( HttpServletRequest request, HttpServletResponse response, FilterChain filterChain ) throws ServletException, IOException {
        try{
            String jwtToken= Objects.requireNonNull ( jwtUtil ).getJwtFromHeader ( request );
            if(Objects.nonNull (jwtToken) && jwtUtil.validateJwtToken (jwtToken)){
                String username = jwtUtil.getUsernameFromJwtToken(jwtToken);
                UserDetailsService userDetailsService = Objects.requireNonNull ( userDetailsServiceProvider ).getIfAvailable();
                UserDetails userDetails = Objects.requireNonNull ( userDetailsService ).loadUserByUsername (username);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails ( new WebAuthenticationDetailsSource ().buildDetails ( request ) );
                SecurityContextHolder.getContext().setAuthentication (authentication);
            }
        }catch (Exception e){
            logger.error (e.getMessage(),e);
        }
        filterChain.doFilter (request, response);
    }
}
