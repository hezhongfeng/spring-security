package com.hezf.demo;

import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import org.slf4j.Logger;

@Component
public class JWTProvider {
  private static final Logger logger = LoggerFactory.getLogger(JWTProvider.class);

  private static final String AUTHORITIES_KEY = "permissions";

  private static SecretKey secretKey;

  @Value("${jwt.secret}")
  public void setJwtSecret(String secret) {
    secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
  }

  private static int jwtExpirationInMs;

  @Value("${jwt.expire}")
  public void setJwtExpirationInMs(int expire) {
    jwtExpirationInMs = expire;
  }

  // generate JWT token
  public static String generateToken(Authentication authentication) {
    long currentTimeMillis = System.currentTimeMillis();
    Date expirationDate = new Date(currentTimeMillis + jwtExpirationInMs * 1000);

    String scope = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(","));

    Claims claims = Jwts.claims().setSubject(authentication.getName());
    claims.put(AUTHORITIES_KEY, scope);
    return Jwts.builder().setClaims(claims).setExpiration(expirationDate)
        .signWith(secretKey, SignatureAlgorithm.HS256).compact();
  }

  public static Authentication getAuthentication(String token) {
    Claims claims =
        Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
    // 从jwt获取用户权限列
    String permissionString = (String) claims.get(AUTHORITIES_KEY);

    List<SimpleGrantedAuthority> authorities =
        permissionString.isBlank() ? new ArrayList<SimpleGrantedAuthority>()
            : Arrays.stream(permissionString.split(",")).map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

    // 获取 username
    String username = claims.getSubject();

    return new UsernamePasswordAuthenticationToken(username, null, authorities);
  }

  // validate Jwt token
  public static boolean validateToken(String token) {
    try {
      Jwts.parserBuilder().setSigningKey(secretKey).build().parse(token);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }
    return false;
  }
}
