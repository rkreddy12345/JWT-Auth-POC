package com.rk.security.jwt.utils;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

@Component
public class JwtUtil {
    private static final Logger logger= LoggerFactory.getLogger(JwtUtil.class);

    @Value ( "${spring.security.jwt.secret}" )
    private String jwtSecret;
    @Value ( "${spring.security.jwt.expire}" )
    private String jwtExpire;

    public String getJwtFromHeader( HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if(Objects.nonNull (bearerToken) && bearerToken.startsWith ( "Bearer " )) {
            return bearerToken.substring ( "Bearer ".length() );
        }
        return null;
    }

    public String generateJwtToken( UserDetails userDetails) {
        return Jwts.builder ()
                .subject ( userDetails.getUsername () )
                .issuedAt ( Date.from ( Instant.now () ) )
                .expiration ( Date.from ( Instant.now ().plusMillis ( Long.parseLong ( jwtExpire ) ) ) )
                .signWith ( getSecretKey () )
                .compact ();
    }

    private SecretKey getSecretKey () {
        return Keys.hmacShaKeyFor ( Decoders.BASE64URL.decode (jwtSecret) );
    }

    public String getUsernameFromJwtToken ( String token) {
        return Jwts.parser ()
                .verifyWith ( getSecretKey () )
                .build ()
                .parseSignedClaims ( token )
                .getPayload ()
                .getSubject ();
    }

    public boolean validateJwtToken (String token) {
        try{
            Jwts.parser ()
                    .verifyWith ( getSecretKey () )
                    .build ()
                    .parseSignedClaims ( token );
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token.", e);
        } catch (ExpiredJwtException e) {
            logger.error("JWT token has expired.", e);
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported.", e);
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty.", e);
        } catch (Exception e) {
            logger.error("Unexpected error during JWT validation.", e);
        }
        return false;
    }
}
