package com.hezf.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {

  // private static ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {
    // response.setContentType("application/json;charset=utf-8");

    // response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

    // response.setContentType("application/json;charset=utf-8");
    // // RespResult<String> resp = new RespResult<String>(201, "未登录，请先登录", null);
    // objectMapper.writeValue(response.getWriter(), resp);
    // return "login";
    response.sendRedirect("login");
  }
}
