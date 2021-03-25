package com.example.demo.security;

import io.jsonwebtoken.*;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

@Component
@Slf4j
public class JwtTokenServices {

    @Value("${security.jwt.token.secret-key:secret}")
    private String secretKey = "secret";

    @Value("${security.jwt.token.expire-length:3600000}")
    private long validityInMilliseconds = 3600000; // 10 hours

    private final String rolesFieldName = "roles";

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // Creates a JWT token
    public String createToken(String username, List<String> roles) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);

        // Add custom field to the token
        Claims claims = Jwts.claims().setSubject(username).setExpiration(validity).setIssuedAt(now);
        claims.put(rolesFieldName, roles);

        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public String getTokenFromRequest(HttpServletRequest req) {
        String bearerKey = "Bearer ";
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith(bearerKey)) {
            return bearerToken.substring(bearerKey.length());
        }
        return null;
    }

    // Checks if token is valid and not expired
    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            if (claims.getBody().getExpiration().before(new Date())) {
                return false;
            }
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("JWT token invalid " + e);
        }
        return false;
    }

    /**
     * Parses the username and roles from the token. Since the token is signed we can be sure it has valid information.
     * Note that it does not make a DB call to be super fast!
     * This could result in returning false data (e.g. the user was deleted, but their token ahs not expired yet)
     * To prevent errors because of this, make sure to check the user in the database for more important calls!
     */
    public Authentication parseUserFromTokenInfo(String token) throws UsernameNotFoundException {
        Claims body = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();
        String username = body.getSubject();
        List<String> roles = (List<String>) body.get(rolesFieldName);
        List<SimpleGrantedAuthority> authorities = new LinkedList<>();
        for (String role : roles) {
            authorities.add(new SimpleGrantedAuthority(role));
        }
        return new UsernamePasswordAuthenticationToken(username, "", authorities);
    }
}
