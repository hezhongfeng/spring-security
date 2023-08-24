# 简介

Spring Security 是一个 Java 框架，用于保护应用程序的安全性。它提供了一套全面的安全解决方案，包括身份验证、授权、防止攻击等功能。Spring Security 基于过滤器链的概念，可以轻松地集成到任何基于 Spring 的应用程序中。它支持多种身份验证选项和授权策略，开发人员可以根据需要选择适合的方式。此外，Spring Security 还提供了一些附加功能，如集成第三方身份验证提供商和单点登录，以及会话管理和密码编码等。总之，Spring Security 是一个强大且易于使用的框架，可以帮助开发人员提高应用程序的安全性和可靠性。

Spring Security 提供了对身份认证、授权和针对常见漏洞的保护的全面支持。

详细点说就是提供了：

认证（Authentication）：可以理解为登录（包括用户名密码、手机号验证码、指纹识别、等等）

授权（Authorization）：对资源的保护，只有拿到该资源的授权才可以访问

漏洞保护：跨域、csrf 等防护

## 项目创建

当前的 Spring Boot 版本是 3.1.2，Spring Security 的版本是 6.1.2

当我们使用 <https://start.spring.io/> 添加 `Spring Web` 创建完成项目

![start](https://gitee.com/hezf/assets/raw/master/202308231407299.png)

创建项目后，新建一个 index 接口，这样就可以在根目录访问接口了

在`src/main/java/com/hezf/demo/DemoApplication.java`同级别目录新建文件`IndexController.java`后，写下第一个接口：

```java
package com.example.hezf;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

  @RequestMapping("/")
  public String index() {
    return "Hello Index!";
  }
}

```

启动项目，访问本地 8080 接口：`http://localhost:8080/`，成功访问到接口数据后，继续下面的操作

## 引入

在 build.gradle 添加 implementation 'org.springframework.boot:spring-boot-starter-security' 添加完成后，需要 gradle 下载引入 security

下载完成后，重新启动项目，继续访问 `http://localhost:8080/`

这时候发现跳转到了一个登录的页面，这就表明 security 已经起作用了，不让我们直接访问接口了，接口被保护了起来

我们查看调试信息，会发现一条类似的信息`Using generated security password: 9d53cf27-6c2b-4468-809a-247eb5d669da`，把这个密码和用户名`user`填上就可以继续访问刚才的接口

在密码出现的下方有一条：This generated password is for development use only. Your security configuration must be updated before running your application in production.

这是告诉我们，这个用户和密码只是在开发阶段调试使用，生产环境不要这么使用，接下来我们自定义用户和密码。session1

## 内存认证

在`src/main/java/com/hezf/demo/DemoApplication.java`同级别目录新建文件`DefaultSecurityConfig.java`，写下：

```java
package com.hezf.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {

  @Bean
  public UserDetailsService users() {

    UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password")
        .roles("user").build();
    return new InMemoryUserDetailsManager(user);
  }

}
```

这时候重启项目，发现控制台没有`Using generated security password`等信息出现了，可以使用 `user` 和 `password` 进行登录，登录后可以访问 IndexController。

这种内存用户可以快速的验证登录和一些权限控制，在项目中添加了 `Spring Security` 之后，默认对所有接口都开启了访问控制，只有已认证用户（已登录）才可以访问，所以才需要登录,接下来我们尝试进行对 security 进行配置。 session2

## SecurityConfig

在项目中添加了 `Spring Security`，必须登录才能访问接口，那么怎么把这个限制关掉，这时候可以使用 SecurityFilterChain，在 DefaultSecurityConfig 添加 SecurityFilterChain

```java
@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http.build();
  }

  @Bean
  public UserDetailsService users() {

    UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password")
        .roles("user").build();

    return new InMemoryUserDetailsManager(user);
  }

}

```

当添加上面的配置重启后，发现接口可以随便访问了，这是因为默认情况下，Spring Security 接口保护、表单登录被启用。然而，只要提供任何 SecurityFilterChain 配置，就必须明确接口保护和基于表单的登录。为了实现之前的接口保护和表单登录，需要如下配置：

```java
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

    http.formLogin(Customizer.withDefaults());

    return http.build();
  }
```

如果想把接口保护去掉，那么上面的配置改为`http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());` 意思就是放行所有请求

## UserDetailsService

前面我们使用了内存用户通过登录获取认证，来访问接口。实际在开发过程中用户信息肯定是要持久化的，要存到数据库中去，这时候最好实现一个 UserDetailsService 用来检索用户名、密码和其他属性。

新建`CustomUserDetailsService.java`文件：

```java
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
        .roles("user").build();

    UserDetails user1 = User.withDefaultPasswordEncoder().username("user1").password("password")
        .roles("user").build();

    userRegistry.put("user", user);
    userRegistry.put("user1", user1);
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

```

DefaultSecurityConfig 修改一下：

```java
@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

    http.formLogin(Customizer.withDefaults());

    return http.build();
  }
}
```

然后就可以用 user 和 user1 完成登录了 session3

## API 接口限制

在实际开发中，有的接口可以随便访问，比如 login 接口，有的接口必须登录后才可以访问，比如查询当前用户信息的接口。有的接口可以管理其他用户，那就必须具有管理员权限才可以访问。

接下来创建 3 种接口，一种不需要登录，一种登录就行，另外一个需要特殊权限才可以访问。首先创建这 3 个接口：

```java
@RestController
public class IndexController {

  // 公开接口，可以随便访问
  @RequestMapping("/public")
  public String index() {
    return "Hello Public!";
  }

  // 需要认证用户才可以访问
  @RequestMapping("/user")
  public String user() {
    return "Hello User!";
  }

  // 需要具有 ADMIN 权限才可以访问
  @RequestMapping("/admin")
  public String admin() {
    return "Hello Admin!";
  }
}
```

接下来配置 SecurityFilterChain：

```java
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    // @formatter:off
    http.authorizeHttpRequests(authorize -> authorize
      .requestMatchers("/public").permitAll() // /public 接口可以公开访问
      .requestMatchers("/admin").hasAuthority("ADMIN") // /admin 接口需要 ADMIN 权限
      .anyRequest().authenticated()); // 其他的所以接口都需要认证才可以访问
    // @formatter:on

    http.formLogin(Customizer.withDefaults());

    return http.build();
  }
```

然后准备用户数据：

```java
  @PostConstruct
  public void init() {

    UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password")
        .authorities("USER").build();

    UserDetails admin = User.withDefaultPasswordEncoder().username("admin").password("password")
        .authorities("ADMIN").build();

    userRegistry.put("user", user);
    userRegistry.put("admin", admin);
  }
```

重启项目访问 `http://localhost:8080/public` 成功访问。接下来访问 `http://localhost:8080/user` 会要求登录，我们输入 user 的用户名和密码，成功访问。接下来访问 `http://localhost:8080/admin` 发现返回了 403 状态吗，告诉我们权限不正确，这时候清空下 cookie 重新使用 admin 登录即可访问。到此，，我们实现了最小型的接口权限控制。session4

## JWT

## 自定义登录接口

## 自定义添加用户

## 多个 SecurityFilterChain

添加完后，重启项目，就可以不登录直接访问之前的接口了。

Spring Security 基于过滤器链的概念，可以轻松地集成到任何基于 Spring 的应用程序中。即通过一层层的 Filters 来对 web 请求做处理。

![filterchainproxy](https://springdoc.cn/spring-security/_images/servlet/architecture/filterchainproxy.png)

接下来说一下 SecurityFilterChain ，SecurityFilterChain 被 FilterChainProxy 用来确定当前请求应该调用哪些 Spring Security Filter 实例。也就是说，Spring Security 的安全管理是一层一层的

同时可以设置多个 SecurityFilterChain，像下面这样：

![multi-securityfilterchain](https://springdoc.cn/spring-security/_images/servlet/architecture/multi-securityfilterchain.png)
