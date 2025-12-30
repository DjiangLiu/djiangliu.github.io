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

## xml配置

## 注解配置

