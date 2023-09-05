package com.hezf.demo;

import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

  @Autowired
  private AuthenticationManager authenticationManager;

  private SecurityContextRepository securityContextRepository =
      new HttpSessionSecurityContextRepository();

  @GetMapping("/login")
  String login() {
    System.out.println("GetMapping login");
    return "login";
  }

  @PostMapping("/login")
  void login(HttpServletRequest request, HttpServletResponse response,
      @RequestParam("username") String username, @RequestParam("password") String password)
      throws IOException, ServletException {
    System.out.println("进入了 登录认证");

    UsernamePasswordAuthenticationToken token =
        UsernamePasswordAuthenticationToken.unauthenticated(username, password);

    Authentication authentication = authenticationManager.authenticate(token);
    // 设置空的上下文
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(authentication);


    SecurityContextHolder.setContext(context);
    // 有这句才认为当前用户登录了
    securityContextRepository.saveContext(context, request, response);

    response.sendRedirect("/public");

    // // 检查是否有之前请求的 URL，如果有就跳转到之前的请求 URL 上去
    // SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
    // if (savedRequest != null) {
    // String targetUrl = savedRequest.getRedirectUrl();
    // response.sendRedirect(targetUrl);
    // // getRedirectStrategy().sendRedirect(request, response, targetUrl);
    // } else {
    // response.sendRedirect("/public");
    // // super.onAuthenticationSuccess(request, response, authentication);
    // }
    // return "login";
  }
}
