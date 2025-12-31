---
title: Spring MVC 拦截器
date: 2025-12-30
categories: 
- Spring MVC
tags: 
- 拦截器
---

```
Spring作为老牌全能型框架，要想拦截请求进行一些统一的处理，我们有Filter、Interceptor、ControllerAdvice、AOP这么多种截面可供选择： Filter——作用在最外层，在请求进入Spring之前就触发，可以用于处理一些网络通信层面的东西； Interceptor——作用在Controller的外层，数据进入Controller层之前，或离开Controller的前后触发； ControllerAdvice——作用在Interceptor之内，数据进入Controller层但还没处理之前触发，用于预处理Controller层的RequestBody和ResponseBody，以及统一异常处理； AOP——作用于自己写的方法。 使用的时候遵循“最小作用域”原理，在保证能统一抽象出来的前提下，选择最近最小的那个截面。
```

# 拦截器配置

```xml
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
```

```java
package com.asset.sec88540;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

public class InterceptorDemo implements HandlerInterceptor{
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        System.out.println("preHandle");
        return true;
    }
    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, ModelAndView modelAndView) throws Exception {
        System.out.println("postHandle");
    }
    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        System.out.println("afterCompletion");
    }
}
```

```java
package com.asset.sec88540.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/index")
public class Index {
    @RequestMapping("/index")
    private String pcPay(String name) {
        String form = name + "欢迎来到PC端支付页面";
        System.out.println(form);
        return form;
    }
}

```

```java
package com.asset.sec88540;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Sec88540Application {

    public static void main(String[] args) {
        SpringApplication.run(Sec88540Application.class, args);
    }

}
```



## xml配置

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:mvc="http://www.springframework.org/schema/mvc"
       xsi:schemaLocation="
        http://www.springframework.org/schema/beans
        http://www.springframework.org/schema/beans/spring-beans.xsd
        http://www.springframework.org/schema/mvc
        http://www.springframework.org/schema/mvc/spring-mvc.xsd">

    <!-- 1. 配置自定义拦截器的Bean实例 -->
    <bean id="interceptordemo" class="com.asset.sec88540.InterceptorDemo"/>

    <!-- 2. 注册拦截器（核心配置：<mvc:interceptors>） -->
    <mvc:interceptors>
        <!-- 方式1：全局拦截器（拦截所有请求，无排除路径） -->
        <!-- 直接嵌套拦截器Bean，对所有DispatcherServlet处理的请求生效 -->
        <!-- <ref bean="customHandlerInterceptor"/> -->

        <!-- 方式2：指定路径拦截器（推荐，精准控制拦截/排除路径） -->
        <mvc:interceptor>
            <!-- 配置需要拦截的路径（支持Ant风格通配符：*匹配单层路径，**匹配多层路径） -->
            <mvc:mapping path="/**"/> <!-- 拦截所有请求 -->
            <!-- 配置需要排除的路径（不拦截的请求，优先级高于mapping） -->
            <mvc:exclude-mapping path="/static/**"/> <!-- 排除静态资源 -->
            <mvc:exclude-mapping path="/login"/> <!-- 排除登录接口 -->
            <!-- 引用自定义拦截器Bean -->
            <ref bean="interceptordemo"/>
        </mvc:interceptor>
    </mvc:interceptors>

</beans>
```

```java
package com.asset.sec88540;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ImportResource;

@ImportResource(locations = "classpath:spring-mvc-interceptor.xml")
@SpringBootApplication
public class Sec88540Application {

    public static void main(String[] args) {
        SpringApplication.run(Sec88540Application.class, args);
    }

}

```



![image-20251231154226823](/images/2025-12-30-SpringMVC拦截器.assets/image-20251231154226823.png)

## 注解配置

```java
package com.asset.sec88540;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;

@Configuration
public class MyWebMvcConfigurerAdapter implements WebMvcConfigurer {
    @Bean
    public InterceptorDemo interceptorDemo() {
        return new InterceptorDemo();
    }
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(interceptorDemo()).addPathPatterns("/**");
    }
}

```

![image-20251231152809018](/images/2025-12-30-SpringMVC拦截器.assets/image-20251231152809018.png)



