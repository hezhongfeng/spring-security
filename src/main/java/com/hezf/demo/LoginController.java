package com.hezf.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

  @GetMapping("/login")
  String login() {
    System.out.println("GetMapping login");
    return "login";
  }
}
