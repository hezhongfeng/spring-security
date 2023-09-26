package com.hezf.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import com.hezf.demo.jwt.JWTFilter;
import com.hezf.demo.session.SessionAccessDeniedHandler;
import com.hezf.demo.session.SessionAuthenticationEntryPoint;
import com.hezf.demo.jwt.JWTAccessDeniedHandler;
import com.hezf.demo.jwt.JWTAuthenticationEntryPoint;

@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {

  @Bean
  @Order(0) // 最高优先级
  public SecurityFilterChain jwtFilterChain(HttpSecurity http) throws Exception {

    // @formatter:off
    http.securityMatcher("/api/**").authorizeHttpRequests(authorize -> authorize
      .requestMatchers("/public","/api/login").permitAll() // /public 接口可以公开访问
      .requestMatchers("/api/admin").hasAuthority("ADMIN") // /admin 接口需要 ADMIN 权限
      .anyRequest().authenticated()); // 其他的所以接口都需要认证才可以访问
      // @formatter:on

    // 设置异常的EntryPoint的处理
    http.exceptionHandling(exceptions -> exceptions
        // 未登录
        .authenticationEntryPoint(new JWTAuthenticationEntryPoint())
        // 权限不足
        .accessDeniedHandler(new JWTAccessDeniedHandler()));

    // 关闭 csrf 保护
    http.csrf(csrf -> csrf.disable());

    // 在过滤器链中添加 JWTFilter
    http.addFilterBefore(new JWTFilter(), LogoutFilter.class);

    return http.build();
  }

  @Bean
  @Order(1) // 次高优先级，处理会话认证
  public SecurityFilterChain sessionFilterChain(HttpSecurity http) throws Exception {

    // @formatter:off
    http.authorizeHttpRequests(authorize -> authorize
      .requestMatchers("/public","/login").permitAll() // /public 接口可以公开访问
      .requestMatchers("/admin").hasAuthority("ADMIN") // /admin 接口需要 ADMIN 权限
      .anyRequest().authenticated()); // 其他的所以接口都需要认证才可以访问
      // @formatter:on

    // 设置异常的EntryPoint的处理
    http.exceptionHandling(exceptions -> exceptions
        // 未登录
        .authenticationEntryPoint(new SessionAuthenticationEntryPoint())
        // 权限不足
        .accessDeniedHandler(new SessionAccessDeniedHandler()));

    // http.formLogin(Customizer.withDefaults());
    // http.formLogin(form -> form.loginPage("/login").permitAll());

    return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManager(
      AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }
}
