package com.hezf.demo;

import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

class LoginRequest {

  private String username;
  private String password;


  public String getUsername() {
    return this.username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return this.password;
  }

  public void setPassword(String password) {
    this.password = password;
  }
}

@RestController
public class LoginController {

  @Autowired
  private AuthenticationManager authenticationManager;

  @PostMapping("/login")
  public Map<String, Object> login(@RequestBody LoginRequest login) {

    Map<String, Object> map = new HashMap<>();

    try {
      UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken
          .unauthenticated(login.getUsername(), login.getPassword());

      Authentication authentication = authenticationManager.authenticate(token);

      String jwt = JWTProvider.generateToken(authentication);

      map.put("jwt", jwt);
    } catch (BadCredentialsException ex) {
      map.put("error", ex.getMessage());
    }
    return map;
  }
}
