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

这是告诉我们，这个用户和密码只是在开发阶段调试使用，生产环境不要这么使用，接下来我们自定义用户和密码。
