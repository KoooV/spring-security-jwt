package com.kov.springsecurityjwt.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Slf4j
@Service
public class JwtService {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expiration;


    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> claims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token) && validateSignature(token));
    }

    public boolean validateSignature(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(getSignInKey())
                    .parseClaimsJws(token);
            return true;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
            return false;

        }
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());//возвращает true если дата токена раньше текущей даты
    }

    private Date extractExpiration(String token) {//вытаскиваем из payload время актуальности токена
        return extractClaim(token, Claims::getExpiration);
    }


    private String extractUsername (String token){
        return extractClaim(token, Claims::getSubject);//вытаскиеваем из payload имя
        }

    public String getUsernameFromToken(String token) throws IllegalAccessException {
        if (token == null || token.trim().isEmpty()) {
            log.error("Token is null or empty");
            throw new IllegalArgumentException("Token is null or empty");
        }
        try {
            String username = extractUsername(token);
            if (username == null || username.trim().isEmpty()) {
                log.error("Username not found in token: {}", token);
                throw new IllegalArgumentException("Username not found in token");
            }
            return username;
        } catch (ExpiredJwtException e) {
            log.warn("Token has expired: {}", e.getMessage());
            throw e;
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid token", e);
        }
    }

    }




