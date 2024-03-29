# Spring Security 简介

`Spring Security` 提供了对身份认证、授权和针对常见漏洞的保护的全面支持，可以轻松地集成到任何基于 `Spring` 的应用程序中。

主要就是提供了：

- 认证（Authentication）：可以理解为登录，验证访问者的身份。包括用户名密码认证、手机号短信验证码认证、指纹识别认证、面容识别认证等等
- 授权（Authorization）：授权发生在系统完成身份认证之后，最终会授予你访问资源（如信息，文件，数据库等等）的权限，授权决定了你访问系统的能力以及达到的程度，比如只有拿到了操作用户的授权，才可以管理用户
- 漏洞保护：跨域、csrf 等防护

就我个人而言，以前对 `Spring Security` 的认识非常不清楚，所以这次从零开始一点一点的尝试了一遍目前能遇到的大多数场景，下面是逐步探索 `Spring Security` 使用方法的整个过程，其中包括：

1. Spring Boot 项目初始化
2. 引入 Spring Security
3. 内存用户登录
4. SecurityConfig
5. UserDetailsService
6. 接口权限限制
7. 获取认证信息
8. 自定义登录页面
9. 自定义登录接口
10. JWT 认证
11. 多个 SecurityFilterChain

## 项目初始化

当前的 `Spring Boot` 版本是 3.1.2，`Spring Security` 的版本是 6.1.2

首先使用 [Spring Initializr](https://start.spring.io/) 添加 `Spring Web` 完成项目的创建

![start](https://gitee.com/hezf/assets/raw/master/202308231407299.png)

创建项目并下载打开后，新建一个 index 接口，这样就可以启动服务，访问接口了

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

## 引入 Spring Security

在 build.gradle 添加 `implementation 'org.springframework.boot:spring-boot-starter-security'` ，完成后需要 gradle 下载引入 security

下载后，重新启动项目，继续访问 `http://localhost:8080/`

这时候发现跳转到了一个登录的页面，这就表明 security 已经起作用了，不让我们直接访问接口了，接口被保护了起来

我们查看调试信息，会发现一条类似的信息`Using generated security password: 9d53cf27-6c2b-4468-809a-247eb5d669da`，把这个密码和用户名`user`填上就可以继续访问刚才的接口

在密码出现的下方有一条：`This generated password is for development use only. Your security configuration must be updated before running your application in production.`

这是告诉我们，这个用户和密码只是在开发阶段调试使用，生产环境不要这么使用，接下来我们自定义用户和密码。

## 内存用户登录

上面的密码使用起来太麻烦了，还是想办法建几个固定账号吧，在`src/main/java/com/hezf/demo/DemoApplication.java`同级别目录新建文件`DefaultSecurityConfig.java`：

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

这时候重启项目，发现控制台没有`Using generated security password`等信息出现了，可以使用 `user` 和 `password` 进行登录，登录后可以访问 IndexController

这种内存用户可以快速的验证登录和一些权限控制，在项目中添加了 `Spring Security` 之后，默认对所有接口都开启了访问控制，只有已认证用户（已登录）才可以访问，接下来我们尝试对 security 进行配置

## SecurityConfig

在项目中添加 `Spring Security`后，必须登录才能访问接口，那么怎么把这个限制关掉？这时候可以使用 `SecurityFilterChain`，在 D`efaultSecurityConfig` 添加 `SecurityFilterChain`：

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

当添加上面的配置重启后，发现接口可以随便访问不需要登录了，这是因为默认情况下，`Spring Security` 的接口保护、表单登录被启用。然而，只要提供 `SecurityFilterChain` 配置，就必须显示启用接口保护和表单登录，否咋就不会生效。为了实现之前的接口保护和表单登录，需要添加如下配置，启用接口保护和表单登录：

```java
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

    http.formLogin(Customizer.withDefaults());

    return http.build();
  }
```

第一句配置了访问任何接口都需要认证，第二句是开启表单登录。如果想把接口保护去掉，那么上面的配置改为`http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());` 意思就是放行所有请求

## UserDetailsService

前面我们使用了内存用户通过登录获取认证，来访问接口。实际在开发过程中用户信息肯定是要持久化的，要存到数据库中去，这时候最好实现一个 `UserDetailsService` 用来检索用户名、密码和其他属性。

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

`DefaultSecurityConfig` 修改一下，去掉 `DefaultSecurityConfig` 中的 `UserDetailsService`：

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

然后就可以用 `user` 和 `user1` 登录了，以上是为了模拟真实的环境，一般在 `loadUserByUsername` 中进行数据库查询用户信息，然后返回装填好信息的 `UserDetails` 进行认证

## 接口权限限制

在实际开发中，有的接口可以随便访问，比如 `login` 接口，有的接口必须登录后才可以访问，比如查询当前用户信息的接口。有的接口可以管理其他用户，那就必须具有管理员权限才可以访问。

接下来创建 3 种接口，一种不需要认证，一种已认证就行，最后一种需要某种权限才可以访问。首先创建这 3 个接口：

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

接下来配置 `SecurityFilterChain`：

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

重启项目访问 `http://localhost:8080/public` 成功访问。接下来访问 `http://localhost:8080/user` 会要求登录，我们输入 `user` 的用户名和密码，成功访问。继续访问 `http://localhost:8080/admin` 发现返回了 `403` 状态吗，告诉我们权限不正确，这时候清空下 `cookie` 重新使用 `admin` 登录即可访问。到此，我们实现了最小型的接口权限控制

## 获取认证信息

当用户第一次访问受保护的接口时，会被重定向到登录页面，这时候后端服务会分配给用户一个会话 ID，存于 `Cookies` 中的 `JSESSIONID`。随后的每次请求都会携带这个 `Cookie`，用于在接下来的会话中认证用户的身份。使用 `SecurityContext` ，可以获取当前用户的认证信息，他们之间的关系可以看图：

![securitycontextholder](https://springdoc.cn/spring-security/_images/servlet/authentication/architecture/securitycontextholder.png)

```java
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
```

上面的代码只有在已认证的情况下才有效，认证的过程是 `Spring Security` 提供的登录页面和接口，下一步自己实现登录过程

## 自定义登录页面

首先尝试自定义登录页面，这样可以直观的看到前端页面是怎么提交用户名、密码的

- 在`build.gradle`添加依赖`implementation "org.springframework.boot:spring-boot-starter-thymeleaf"`
- 新建 `src/main/resources/templates/login.html` 页面：

```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="https://www.thymeleaf.org">
  <head>
    <title>Custom Log In Page</title>
  </head>
  <body>
    <h1>Please Log In</h1>
    <div th:if="${param.error}">Invalid username and password.</div>
    <div th:if="${param.logout}">You have been logged out.</div>
    <form th:action="@{/login}" method="post">
      <div>
        <input type="text" name="username" placeholder="Username" />
      </div>
      <div>
        <input type="password" name="password" placeholder="Password" />
      </div>
      <input type="submit" value="Log in" />
    </form>
  </body>
</html>
```

- 再配置文件 `DefaultSecurityConfig`：

```java
 http.formLogin(form -> form.loginPage("/login").permitAll());
```

- 新建文件`src/main/java/com/hezf/demo/LoginController.java`:

```java
package com.hezf.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

  @GetMapping("/login")
  String login() {
    return "login";
  }
}

```

这时候重启项目，继续访问 `/user` ，会跳转到我们自定义的登录页面，其他和以前的一样。前面的配置修改是告诉 `spring security` 我们有自己的登录页面请求接口，`LoginController` 是为了返回这个自定义登录页面，上面添加的 `thymeleaf` 是为了解析登录页面 `login.html`

## 自定义登录接口

前面我们自定义了登录页面，如果想自己定义登录接口，就需要把默认的 `formLogin` 关掉，否则即使声明了 `POST` 方法的 `login` 接口也没用，登录请求会被`formLogin` 拦截。所以我们直接注释掉 `formLogin` 相关就可以了，这里并不需要将 `formLogin` disabled 什么的。有了默认的 `SecurityFilterChain` 后，默认 `formLogin` 就是关掉的

- 修改 `DefaultSecurityConfig`，这里需要注意，需要把 `login` 接口开放出来，这里新增了两个异常处理，因为我想实现未登录自动跳转到登录页面

```java
@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

    // @formatter:off
    http.authorizeHttpRequests(authorize -> authorize
      .requestMatchers("/public","/login").permitAll() // /public 接口可以公开访问
      .requestMatchers("/admin").hasAuthority("ADMIN") // /admin 接口需要 ADMIN 权限
      .anyRequest().authenticated()); // 其他的所以接口都需要认证才可以访问
      // @formatter:on

    // 设置异常的EntryPoint的处理
    http.exceptionHandling(exceptions -> exceptions
        // 未登录
        .authenticationEntryPoint(new MyAuthenticationEntryPoint())
        // 权限不足
        .accessDeniedHandler(new MyAccessDeniedHandler()));

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
```

- 添加上面的两个异常处理 `MyAuthenticationEntryPoint` 和 `MyAccessDeniedHandler`，分别是未登录和未授权

```java
package com.hezf.demo;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
public class MyAuthenticationEntryPoint implements AuthenticationEntryPoint {

  @Override
  public void commence(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException authException) throws IOException, ServletException {
    response.sendRedirect("login");
  }
}
```

```java
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
    objectMapper.writeValue(response.getWriter(), "没有对应的权限");
  }
}

```

- 添加请求登录接口，这里完成了登录信息的验证，后续 `http` 请求上下文的保存还有自动跳转之前请求的链接

```java
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
```

运行项目，浏览器直接访问 `http://localhost:8080/user` 会自动跳转到自定义登录页面，输入 `user` 用户名和密码后，会自动跳转回刚才访问的 `http://localhost:8080/user`，这时候继续访问 `http://localhost:8080/admin` 会返回 `"没有对应的权限"`，到这里我们就完成了：

1. 自定义用户名密码验证的页面和接口
2. 未登录自动跳转到登录页面
3. 登录后自动跳转到之前想访问的接口
4. 接口权限验证

## JWT 认证

上面我们完成了自定义的接口，自动跳转等等。。。但是现在更普遍的是前后端分离的项目，这样更容易扩展应用场景。下面来实现登录后颁发 `jwt`，以及通过 `jwt` 来进行认证和权限判断

- 引入所需的 `jwt` 库

```yml
// jwt相关
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
```

- 添加 `jwt` 的默认配置

在 `src/main/resources` 下删除原来的 `application.properties`，并且创建文件 `src/main/resources/application.yml`，填入以下内容：

```yml
jwt:
  # 60*60*1
  expire: 3600
  # secret: 秘钥(普通字符串)
  secret: pa1R0cHM6hyGf8Hyb7D34LKJ8b4gldC91LzM2ODE4Njg
```

- 添加颁发、解析、认证 `jwt` 等工具类

新建 `src/main/java/com/hezf/demo/JWTProvider.java` 文件，这个类的作用是：

1、生成 `jwt`（在登录的时候生成，根据 `username` 和对应的权限列表）
2、检验 `jwt` 有效性和提取 `jwt` 中的认证信息（使用 `jwt` 访问接口的时候）

```java
@Component
public class JWTProvider {
  private static final Logger logger = LoggerFactory.getLogger(JWTProvider.class);

  private static final String AUTHORITIES_KEY = "permissions";

  private static SecretKey secretKey;

  @Value("${jwt.secret}")
  public void setJwtSecret(String secret) {
    secretKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
  }

  private static int jwtExpirationInMs;

  @Value("${jwt.expire}")
  public void setJwtExpirationInMs(int expire) {
    jwtExpirationInMs = expire;
  }

  // generate JWT token
  public static String generateToken(Authentication authentication) {
    long currentTimeMillis = System.currentTimeMillis();
    Date expirationDate = new Date(currentTimeMillis + jwtExpirationInMs * 1000);

    String scope = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(","));

    Claims claims = Jwts.claims().setSubject(authentication.getName());
    claims.put(AUTHORITIES_KEY, scope);
    return Jwts.builder().setClaims(claims).setExpiration(expirationDate)
        .signWith(secretKey, SignatureAlgorithm.HS256).compact();
  }

  public static Authentication getAuthentication(String token) {
    Claims claims =
        Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
    // 从jwt获取用户权限列
    String permissionString = (String) claims.get(AUTHORITIES_KEY);

    List<SimpleGrantedAuthority> authorities =
        permissionString.isBlank() ? new ArrayList<SimpleGrantedAuthority>()
            : Arrays.stream(permissionString.split(",")).map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

    // 获取 username
    String username = claims.getSubject();

    return new UsernamePasswordAuthenticationToken(username, null, authorities);
  }

  // validate Jwt token
  public static boolean validateToken(String token) {
    try {
      Jwts.parserBuilder().setSigningKey(secretKey).build().parse(token);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }
    return false;
  }
}

```

新建`src/main/java/com/hezf/demo/JWTFilter.java`文件，这个类的作用是：

1、除了登录接口以外，其他接口在进入接口之前，都需要经过 `JWTFilter` 的处理
2、验证 `jwt` 的合法性和有效期等
3、提取 `jwt` 中的 `username` 和 权限，生成 `Authentication` 存到 `security` 上下文
4、`security` 上下文中有了 `Authentication` ，那就代表着已认证，后续也可以在接口中使用 `Authentication` 中的信息

```java

@Component
public class JWTFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(JWTFilter.class);

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    // 这部分出错后，直接返回401，不再走后面的filter
    try {
      // 从请求头中获取jwt
      String jwt = getJwtFromRequest(request);

      // 校验 jwt 是否有效，包含了过期的验证
      if (StringUtils.hasText(jwt) && JWTProvider.validateToken(jwt)) {

        // 通过 jwt 获取认证信息
        Authentication authentication = JWTProvider.getAuthentication(jwt);

        // 将认证信息存入 Security 上下文中，可以取出来使用，也代表着已认证
        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    } catch (Exception ex) {
      LOGGER.error("Could not set user authentication in security context", ex);
    }

    filterChain.doFilter(request, response);
  }

  private String getJwtFromRequest(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");

    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7, bearerToken.length());
    }
    return null;
  }
}

```

- 修改 `springsecurity` 配置，因为使用了 `jwt` 进行认证，所以不需要 `csrf` 保护了

```java
  // 关闭 csrf 保护
  http.csrf(csrf -> csrf.disable());

  // 在过滤器链中添加 JWTFilter
  http.addFilterBefore(new JWTFilter(), LogoutFilter.class);
```

- 重写登录接口，像上次一样，提取 `username` 和 `password` 进行认证，认证成功以后返回 `jwt`，失败的话返回错误信息

```java
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

```

上面的 `authenticationManager.authenticate(token);` 这句会完成用户名密码的认证工作，会调用 `CustomUserDetailsService.loadUserByUsername` 后进行对比，失败后返回错误信息

- 测试接口

使用 `postman` 等测试工具，发起 `post` 请求，格式为 `json`

1. 当发送的用户名密码错误的时候，返回 `{"error":"用户名或密码错误"}`
2. 正确的话返回 `{"jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwicGVybWlzc2lvbnMiOiJVU0VSIiwiZXhwIjoxNjk1MzUxODAyfQ._cNekfYovmnjWKBaKVCiErzu76q-Aj3gZhUsDiITzAA"}`
3. 在 header 中添加 Authorization，并填写值 `Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwicGVybWlzc2lvbnMiOiJVU0VSIiwiZXhwIjoxNjk1MzUxODAyfQ._cNekfYovmnjWKBaKVCiErzu76q-Aj3gZhUsDiITzAA`，后面的一长串就是上一步得到的 jwt，
4. 发起 GET 请求 `http://127.0.0.1:8080/user`，这时候得到 `Hello User!`
5. 继续发起 GET 请求 `http://127.0.0.1:8080/user`，这时候得到 `"没有对应的权限"`

## 多个 SecurityFilterChain

接下来来看一个更加复杂的情况，如何在已经使用会话做认证的情况下，添加 `JWT` 认证做 `API` 接口管理？也就是说，需要同时支持两种认证：

1. 会话认证：访问需要认证的页面，没有认证的情况下自动跳转到登录页面，登录成功后自动跳回刚才访问的页面
2. `JWT` 认证：支持通过 `API` 接口进行登录和访问 `API` 接口

答案是同时可以设置多个 `SecurityFilterChain`，然后根据访问不同的 `URL` 确定使用哪个 `SecurityFilterChain`，只有第一个匹配的 `SecurityFilterChain` 被调用，如下所示：

![multi-securityfilterchain](https://springdoc.cn/spring-security/_images/servlet/architecture/multi-securityfilterchain.png)

如果请求的 `URL` 是 `/api/user/`，它首先与 `/api/**` 的 `SecurityFilterChain0` 模式匹配，所以只有 `SecurityFilterChain0` 被调用，尽管它也与 `SecurityFilterChain1` 匹配,但是只调用第一个匹配的

- 首先准备好两套登录接口

```java
// src/main/java/com/hezf/demo/jwt/JWTLoginController.java
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
@RequestMapping("/api")
public class JWTLoginController {

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
```

```java
// src/main/java/com/hezf/demo/session/SessionLoginController.java
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

```

- 然后准备好两套未认证和权限错误的处理，这部分代码不贴了，可以自行查找：

```java

// JWT
src/main/java/com/hezf/demo/jwt/JWTAuthenticationEntryPoint.java
src/main/java/com/hezf/demo/jwt/JWTAccessDeniedHandler.java

// session
src/main/java/com/hezf/demo/session/SessionAuthenticationEntryPoint.java
src/main/java/com/hezf/demo/session/SessionAccessDeniedHandler.java
```

- 继续准备好两套 user 和 admin 的接口

```java
src/main/java/com/hezf/demo/jwt/JWTController.java
src/main/java/com/hezf/demo/session/SessionController.java
```

- `JWT` 所需的 `JWTProvider` 和 `JWTFilter` 内容不变
- 最后是配置 `SecurityFilterChain`

```java
@EnableWebSecurity
@Configuration
public class DefaultSecurityConfig {

  @Bean
  @Order(0) // 最高优先级，这里处理的都是以 /api/** 开头的接口，使用 jwt 做认证
  public SecurityFilterChain jwtFilterChain(HttpSecurity http) throws Exception {

    // @formatter:off
    http.securityMatcher("/api/**").authorizeHttpRequests(authorize -> authorize
      .requestMatchers("/api/login").permitAll() // /public 接口可以公开访问
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

    return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManager(
      AuthenticationConfiguration authenticationConfiguration) throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }
}
```

最后的结构是这样的，也可以查看源码：

![结构](https://gitee.com/hezf/assets/raw/master/202309261023461.png)

最后我们进行测试，首先是会话认证：

1. 启动项目后，在浏览器访问 `http://localhost:8080/user` ,会自动跳转到 `http://localhost:8080/login`
2. 输入用户名、密码后，会自动跳回 `http://localhost:8080/user`，并显示 `Hello User!`
3. 最后，将浏览器 访问地址改为 `http://localhost:8080/admin` ,会显示 `没有对应的权限` ，会话认证基本验证完成

接下来测试 `JWT` 认证：

1. 使用调试工具 POST `http://localhost:8080/api/login`，body 里面填写 `{"username": "user","password": "password"}`
2. 登录成功后，获取返回值，复制 jwt 的值，在 Header 中添加 `Authorization: Bearer jwt的值`
3. 访问 GET `http://localhost:8080/api/user`，可以正常访问接口，然后携带相同的 Header 继续访问 `http://localhost:8080/api/admin`, 返回 `没有对应的权限`

以上说明，两个 `SecurityFilterChain` 都在运行，并且都是独立的，互不影响。这样做的好处是可以给单独某一些 `API` 设置独有的认证授权，和其他的互不影响。

## 总结

好了，目前完成了较复杂的 `Spring Security` 配置、认证和权限验证。整个过程下来之后，认识了一些`Spring Security` 的默认规则和常用的方法套路，大部分的场景都可以覆盖。根据以上内容可实现基于 `RBAC` 的访问控制，这部分内容可以参考以前的[项目](https://github.com/hezhongfeng/spring-boot-rbac)，一般的项目基本上够用了。
