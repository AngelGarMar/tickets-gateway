package com.tickets.gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
public class JwtUtil {
    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${app.maintenance.secret-key}")
    private String secretKey;

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isExpired(String token) { //retorna true si el token ya expiró
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token); //parseEncryptedClaims(token)
            return false;
        } catch (ExpiredJwtException e) {
            log.info("isExpired: {}", e.getMessage());
            return true;
        }
    }

    public boolean isInvalid(String token) { //retorna true si el token es corrupto o inválido
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token); //parseEncryptedClaims(token)
            return false;
        } catch (Exception e) {
            log.info("isInvalid: {}", e.getMessage());
            return true;
        }
    }

    public Claims getClaims(String token) { //extrae los datos (claims) del token
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token) //parseEncryptedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            log.info("getClaims: {}", e.getMessage());
            return e.getClaims();
        }
    }
}
