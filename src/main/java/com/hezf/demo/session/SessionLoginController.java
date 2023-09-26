package com.hezf.demo.session;

import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class SessionLoginController {

  @Autowired
  private AuthenticationManager authenticationManager;

  private SecurityContextRepository securityContextRepository =
      new HttpSessionSecurityContextRepository();

  @GetMapping("/login")
  String login() {
    return "login";
  }

  @PostMapping("/login")
  void login(HttpServletRequest request, HttpServletResponse response,
      @RequestParam("username") String username, @RequestParam("password") String password)
      throws IOException, ServletException {

    UsernamePasswordAuthenticationToken token =
        UsernamePasswordAuthenticationToken.unauthenticated(username, password);

    // 通过前端发来的 username、password 进行认证，这里会用到CustomUserDetailsService.loadUserByUsername
    Authentication authentication = authenticationManager.authenticate(token);
    // 设置空的上下文
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    // 设置认证信息
    context.setAuthentication(authentication);

    // 这句保证了随后的请求都会有这个上下文，通过回话保持，在前端清理 cookie 之后也就失效了
    securityContextRepository.saveContext(context, request, response);

    // 检查是否有之前请求的 URL，如果有就跳转到之前的请求 URL 上去
    SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
    if (savedRequest != null) {
      String targetUrl = savedRequest.getRedirectUrl();
      response.sendRedirect(targetUrl);
    } else {
      response.sendRedirect("/public");
    }
  }
}
