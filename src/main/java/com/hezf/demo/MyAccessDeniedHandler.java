package com.hezf.demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
public class MyAccessDeniedHandler implements AccessDeniedHandler {

  private static ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response,
      AccessDeniedException accessDeniedException) throws IOException, ServletException {

    response.setContentType("application/json;charset=utf-8");

    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

    response.setContentType("application/json;charset=utf-8");
    // RespResult<String> resp = new RespResult<String>(201, "没有对应的权限", null);
    objectMapper.writeValue(response.getWriter(), "没有对应的权限");
  }
}
