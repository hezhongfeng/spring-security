package com.hezf.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    // @formatter:off
    http.authorizeHttpRequests(authorize -> authorize
      .requestMatchers("/public").permitAll() // /public 接口可以公开访问
      .requestMatchers("/admin").hasAuthority("ADMIN") // /admin 接口需要 ADMIN 权限
      .anyRequest().authenticated()); // 其他的所以接口都需要认证才可以访问
    // @formatter:on

    // http.formLogin(Customizer.withDefaults());
    http.formLogin(form -> form.loginPage("/login").permitAll());

    return http.build();
  }
}
