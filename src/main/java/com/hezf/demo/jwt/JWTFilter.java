package com.hezf.demo.jwt;

import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import java.io.IOException;

@Component
public class JWTFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(JWTFilter.class);

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    // 这部分出错后，直接返回401，不再走后面的filter
    try {
      // 从请求头中获取jwt
      String jwt = getJwtFromRequest(request);

      // 校验 jwt 是否有效，包含了过期的验证
      if (StringUtils.hasText(jwt) && JWTProvider.validateToken(jwt)) {

        // 通过 jwt 获取认证信息
        Authentication authentication = JWTProvider.getAuthentication(jwt);

        // 将认证信息存入 Security 上下文中，可以取出来使用，也代表着已认证
        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    } catch (Exception ex) {
      LOGGER.error("Could not set user authentication in security context", ex);
    }

    filterChain.doFilter(request, response);
  }

  private String getJwtFromRequest(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");

    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7, bearerToken.length());
    }
    return null;
  }
}
