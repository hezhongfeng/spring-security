package com.hezf.demo;

import java.util.HashMap;
import java.util.Map;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;

@Service
public class CustomUserDetailsService implements UserDetailsService {

  private final Map<String, UserDetails> userRegistry = new HashMap<>();

  @PostConstruct
  public void init() {

    UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password")
        .authorities("USER").build();

    UserDetails admin = User.withDefaultPasswordEncoder().username("admin").password("password")
        .authorities("ADMIN").build();

    userRegistry.put("user", user);
    userRegistry.put("admin", admin);
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    // 生产这里是去数据库查询用户
    UserDetails userDetails = userRegistry.get(username);
    if (userDetails == null) {
      throw new UsernameNotFoundException(username);
    }
    return userDetails;
  }

}
