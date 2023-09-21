package com.hezf.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;




@RestController
public class IndexController {


  // private SecurityContextRepository securityContextRepository =
  // new HttpSessionSecurityContextRepository();

  // 公开接口，可以随便访问
  @RequestMapping("/public")
  public String index() {
    return "Hello Public!";
  }

  // 需要认证用户才可以访问
  @RequestMapping("/user")
  public String user() {
    // 静态工具类 SecurityContextHolder 可以获取当前的 SecurityContext 也就是上下文
    SecurityContext context = SecurityContextHolder.getContext();
    // 认证，通过 authentication 可以获取当前用户的一些信息
    Authentication authentication = context.getAuthentication();

    // 检查是否已认证
    System.out.println(authentication.isAuthenticated());

    // 检查用户详情
    UserDetails userDetail = (UserDetails) authentication.getPrincipal();
    System.out.println(userDetail.getUsername());
    System.out.println(userDetail.getPassword()); // 这里是没有密码的
    System.out.println(userDetail.getAuthorities());

    return "Hello User!";
  }

  // 需要具有 ADMIN 权限才可以访问
  @RequestMapping("/admin")
  public String admin() {
    return "Hello Admin!";
  }
}
