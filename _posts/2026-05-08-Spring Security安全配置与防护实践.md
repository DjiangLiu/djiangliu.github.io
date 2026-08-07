---
layout: post
title: "Spring Security 安全配置与防护实践"
date: 2026-05-08 10:00:00 +0800
categories: 
  - Java安全
  - Spring
tags: 
  - Spring Security
  - 认证授权
  - @PreAuthorize
  - CSRF
  - OAuth2
  - Actuator
  - 代码审计
series: Java Web 认证授权安全系列
series_order: 2
---

# Spring Security 安全配置与防护实践

Spring Security 是 Java 生态中最强大的安全框架，但其 "约定大于配置" 的理念也意味着误配置的高发。本文从攻击者视角梳理 8 大常见误配置，并给出生产级修复方案。

> 本文是 [Java Web 认证授权安全系列](/2026/05/07/java-web-auth-overview/) 的第二篇。概览篇提供了框架识别、CVE 版本速查和审计脚本。

---

## 2.1 最致命的误配置：`web.ignoring()` ≠ `permitAll()`

这是代码审计中最常发现的高危问题。两者的行为完全不同：

```java
// ❌ 危险：web.ignoring() 将路径完全移出安全过滤器链
// 该路径上所有安全机制（认证、授权、CSRF、Session 管理等）全部失效
@Bean
public WebSecurityCustomizer webSecurityCustomizer() {
    return web -> web.ignoring()
        .requestMatchers("/api/public/**", "/actuator/health");
}

// ✅ 正确：permitAll() 仅跳过认证，仍保留 CSRF、Session 等安全机制
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(auth -> auth
        .requestMatchers("/api/public/**").permitAll()
        .anyRequest().authenticated()
    );
    return http.build();
}
```

**关键区别**：

| 特性 | `web.ignoring()` | `permitAll()` |
|------|:---:|:---:|
| 认证检查 | 跳过 | 跳过 |
| 授权检查 | 跳过 | 跳过 |
| CSRF 防护 | **跳过** | 保留 |
| Session 管理 | **跳过** | 保留 |
| SecurityContext | **不存在** | 匿名用户 |
| `@PreAuthorize` | **不生效** | 生效 |

> **真实案例**：某金融系统使用 `web.ignoring()` 放行了 `/api/internal/**` 路径，攻击者发现后直接访问 `/api/internal/admin/users` 获取了所有用户数据——该路径上的 `@PreAuthorize("hasRole('ADMIN')")` 完全被无视。

---

## 2.2 过滤器链顺序与多重安全配置

Spring Boot 中如果有多个 `SecurityFilterChain` Bean，它们按 `@Order` 顺序匹配，**第一个匹配的链生效**：

```java
// ❌ 危险：宽泛的匹配优先于精细匹配
@Bean
@Order(1)
public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/api/**")  // 匹配所有 /api/
        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
    return http.build();
}

@Bean
@Order(2)
public SecurityFilterChain adminFilterChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/api/admin/**")  // 永远不会生效！
        .authorizeHttpRequests(auth -> auth.anyRequest().hasRole("ADMIN"));
    return http.build();
}
```

**修复**：将精细匹配放在前面，或使用单一过滤器链配合 `requestMatchers()` 细粒度控制。

---

## 2.3 方法级安全：`@PreAuthorize` 失效场景

```java
// ❌ 如果忘记启用方法级安全，所有 @PreAuthorize 注解都会被忽略！

// Spring Security 6.x 需要：
@EnableMethodSecurity  // ← 新 API

// Spring Security 5.x 需要：
@EnableGlobalMethodSecurity(prePostEnabled = true)  // ← 旧 API

// 两者功能等价，但注解名不同。如果 @PreAuthorize 生效了但你没找到
// @EnableMethodSecurity，去搜索 @EnableGlobalMethodSecurity —
// 它可能藏在父配置类、其他模块、或 XML 里。
```

**排查命令**：

```bash
# 搜索所有可能启用方法安全的注解
grep -rn "EnableMethodSecurity\|EnableGlobalMethodSecurity\|global-method-security" --include="*.java" --include="*.xml" .
```

**隐式开启的情况**：

| 场景 | 注解在哪 |
|------|----------|
| 你的 `SecurityConfig` 继承了某父类 | 父类上有 `@EnableGlobalMethodSecurity` |
| 多模块项目 | 在 `common` 或 `base` 模块的配置里 |
| XML 配置 | `<global-method-security pre-post-annotations="enabled"/>` |
| 第三方 Starter | 公司内部封装的 `xxx-spring-boot-starter` 自动配置 |

**参数化类型注解丢失（CVE-2025-22223）**：Spring Security 6.4.0 ~ 6.4.3 中，如果注解写在参数化父类/接口上而非目标方法上，授权检查可能被绕过。修复：升级到 6.4.4+，或将注解直接放在目标方法上。

---

## 2.4 BCrypt 认证陷阱（CVE-2025-22228）

Spring Security 的 `BCryptPasswordEncoder.matches()` 在 6.3.8 / 6.4.4 之前只比较密码的前 **72 个字符**：

```java
// 以下两个密码在 BCrypt 眼中是"相同"的（前72字符一致）
String pass1 = "a".repeat(72) + "rest_of_password_1";
String pass2 = "a".repeat(72) + "rest_of_password_2";
// BCryptPasswordEncoder.matches() 会错误地返回 true！
```

**修复**：升级到 spring-security-crypto 6.3.8+ / 6.4.4+，或在应用层限制密码最大长度。

---

## 2.5 Actuator 端点暴露与认证绕过

Spring Boot Actuator 暴露后极其危险。更糟糕的是，配置不当可能导致认证绕过：

**CVE-2025-22235（CVSS 7.3）**：当 Actuator 端点被禁用后，`EndpointRequest.to()` 会错误匹配 `/null/**` 路径，导致原本受保护的路径被绕过。

```java
// ❌ 危险（Spring Security < 修复版本）
http.authorizeHttpRequests(auth -> auth
    .requestMatchers(EndpointRequest.to(HealthEndpoint.class)).permitAll()
    // 如果 HealthEndpoint 被禁用，这会匹配 /null/** → 放行大量路径
    .anyRequest().authenticated()
);
```

**CVE-2026-22733**：应用端点挂载在 `/cloudfoundryapplication/` 路径下时，认证可能被绕过。

**防御**：
- 不将 Actuator 暴露在公网
- 为 Actuator 单独设置端口：`management.server.port=8081`
- 始终为 Actuator 端点配置认证
- 升级到最新版本

---

## 2.6 CORS 误配置

```java
// ❌ 危险：允许所有来源
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(Arrays.asList("*"));       // 允许任意来源
    config.setAllowedMethods(Arrays.asList("*"));       // 允许任意方法
    config.setAllowCredentials(true);                   // 允许携带凭证
    return new UrlBasedCorsConfigurationSource();
}
```

**正确做法**：白名单模式，明确指定允许的来源和方法。

---

## 2.7 Spring Security 加固速查

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // 必须显式启用
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/actuator/**").hasRole("MONITORING")
                .anyRequest().authenticated()
            )
            .requiresChannel(channel -> channel.anyRequest().requiresSecure())
            .formLogin(form -> form.defaultSuccessUrl("/"))
            .sessionManagement(session -> session
                .sessionFixation().migrateSession()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            )
            .headers(headers -> headers
                .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter
                    .HeaderValue.ENABLED_MODE_BLOCK))
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives("default-src 'self'"))
            );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
```

```yaml
# application.yml - Actuator 独立端口
management:
  server:
    port: 8081
  endpoints:
    web:
      exposure:
        include: "health,info"
```

---

## 2.8 方法级鉴权详解：`@PreAuthorize` 权限模型

### 2.8.1 `hasRole()` vs `hasAuthority()` vs `hasPermission()`

```java
// ① hasRole("ADMIN") — 自动加前缀 ROLE_
@PreAuthorize("hasRole('ADMIN')")

// ② hasAuthority('circle:admin:list') — 精确匹配
@PreAuthorize("hasAuthority('circle:admin:list')")

// ③ hasPermission(target, permission) — 需自定义 PermissionEvaluator
@PreAuthorize("hasPermission(#orderId, 'ORDER', 'READ')")
```

| 注解 | 前缀处理 | 粒度 | 使用场景 |
|------|:--:|------|----------|
| `hasRole('ADMIN')` | 自动加 `ROLE_` 前缀 | 粗粒度 | 角色级别 |
| `hasAuthority('perm')` | **不做任何处理** | 中粒度 | 权限字符串级别 |
| `hasPermission(...)` | 需实现 `PermissionEvaluator` | 细粒度 | 资源实例级别 |

> **最常见的坑**：误用 `hasRole('circle:admin:list')` 期望匹配权限字符串，实际会被转成 `ROLE_circle:admin:list`，永远匹配不上。

### 2.8.2 权限命名规范（`module:resource:action`）

```
circle : admin : list
  │        │       │
 模块    资源    操作
```

### 2.8.3 完整实现链路：DB → UserDetailsService → @PreAuthorize

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) {
        User user = userMapper.findByUsername(username);
        List<String> permissions = permissionMapper.findByUserId(user.getId());
        
        List<SimpleGrantedAuthority> authorities = permissions.stream()
            .map(SimpleGrantedAuthority::new)  // ← 不做任何前缀处理
            .collect(Collectors.toList());
        
        return new User(user.getUsername(), user.getPassword(),
            user.getEnabled(), true, true, true, authorities);
    }
}
```

```java
// Controller 中使用
@PreAuthorize("hasAuthority('circle:admin:list')")
@GetMapping("/list")
public CommonResult<CommonPage<SystemAdminResponse>> getList(...) { }

// SpEL 组合条件
@PreAuthorize("hasAuthority('circle:admin:add') or hasAuthority('circle:super:add')")
@PostMapping("/add")
public CommonResult<Void> addAdmin(...) { }
```

### 2.8.4 自定义 PermissionEvaluator（资源级鉴权）

```java
@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {
    @Autowired private OrderService orderService;
    
    @Override
    public boolean hasPermission(Authentication auth, Object targetId,
                                  Object targetType, Object permission) {
        Long orderId = (Long) targetId;
        String username = auth.getName();
        Long userId = userService.getUserId(username);
        Order order = orderService.findById(orderId);
        return order != null && order.getUserId().equals(userId);
    }
}
```

### 2.8.5 常见失效场景

| 失效场景 | 原因 | 修复 |
|----------|------|------|
| 注解不生效 | SS 6.x 缺 `@EnableMethodSecurity`；SS 5.x 缺 `@EnableGlobalMethodSecurity(prePostEnabled=true)` | 检查版本，加对应注解 |
| 你搜不到注解但它生效了 | 在父类、XML、其他模块或 Starter 里隐式开启了 | `grep -rn "EnableMethod\|EnableGlobal"` 全局搜索 |
| 内部调用失效 | Spring AOP 代理不拦截 self-invocation | 拆分 Bean 或用 `AopContext.currentProxy()` |
| 参数化类型丢失 | SS 6.4.0-6.4.3 Bug (CVE-2025-22223) | 升级 6.4.4+ |
| `hasRole("perm")` 匹配不上 | 自动加 `ROLE_` 前缀 | 改用 `hasAuthority("perm")` |
| 异步方法丢失 SecurityContext | 线程切换 | `MODE_INHERITABLETHREADLOCAL` |

### 2.8.6 URL 层 + 方法层分层防御

```java
// URL 层：粗粒度角色检查
http.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/admin/**").hasAnyAuthority("ROLE_ADMIN", "ROLE_SUPER_ADMIN")
    .anyRequest().authenticated()
);

// 方法层：细粒度权限检查
@PreAuthorize("hasAuthority('circle:admin:list')")
@GetMapping("/list")
public CommonResult<?> list() { ... }
```

---

## 2.9 CSRF 防护详解

CSRF 是 Spring Security 默认启用的防护，但 RESTful API 时代常常被误关。

### AJAX/API 的 CSRF 处理

```java
// ✅ 分离配置：浏览器页面保留 CSRF，纯 API 可以关闭
@Bean
@Order(1)
public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/api/**")
        .csrf(csrf -> csrf.disable())  // API 用 Token 认证，无 CSRF 风险
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // ... JWT 配置
    return http.build();
}

@Bean
@Order(2)
public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/admin/**", "/user/**")
        // 保留 CSRF 防护 — 页面使用 Cookie/Session
        .csrf(csrf -> csrf
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
        )
        // ...
    return http.build();
}
```

### CSRF Token 前端集成

```javascript
// 前端 Ajax 自动携带 CSRF Token
const csrfToken = document.querySelector('meta[name="_csrf"]').content;
const csrfHeader = document.querySelector('meta[name="_csrf_header"]').content;

fetch('/api/admin/users', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        [csrfHeader]: csrfToken
    },
    body: JSON.stringify(data)
});
```

```html
<!-- Thymeleaf 模板中自动注入 -->
<meta name="_csrf" th:content="${_csrf.token}"/>
<meta name="_csrf_header" th:content="${_csrf.headerName}"/>
```

---

## 2.10 OAuth2 Resource Server 快速配置

```java
// ✅ Spring Security 作为 OAuth2 Resource Server
@Bean
public SecurityFilterChain resourceServerFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/public/**").permitAll()
            .requestMatchers("/api/admin/**").hasAuthority("SCOPE_admin")
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt
                .decoder(jwtDecoder())
                .jwtAuthenticationConverter(jwtAuthConverter())
            )
        )
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    return http.build();
}

@Bean
public JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder
        .withJwkSetUri("https://auth.example.com/.well-known/jwks.json")
        .jwsAlgorithm(JWSAlgorithm.RS256)  // 严格指定算法
        .build();
}

// 将 JWT claims 中的自定义字段映射为 GrantedAuthority
@Bean
public JwtAuthenticationConverter jwtAuthConverter() {
    JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
    converter.setAuthorityPrefix("");  // 不加 SCOPE_ 前缀
    converter.setAuthoritiesClaimName("permissions");  // 从 permissions claim 读取
    
    JwtAuthenticationConverter authConverter = new JwtAuthenticationConverter();
    authConverter.setJwtGrantedAuthoritiesConverter(converter);
    return authConverter;
}
```

---

## 2.11 SpEL 表达式速查（`@PreAuthorize`）

| 表达式 | 说明 |
|--------|------|
| `hasRole('ADMIN')` | 有 ROLE_ADMIN 角色 |
| `hasAuthority('user:read')` | 有精确权限 |
| `hasAnyRole('ADMIN','MANAGER')` | 多个角色任一 |
| `hasAnyAuthority('a','b')` | 多个权限任一 |
| `isAuthenticated()` | 已认证（非匿名） |
| `isAnonymous()` | 匿名用户 |
| `permitAll()` | 所有人（含匿名） |
| `denyAll()` | 拒绝所有人 |
| `#username == authentication.name` | 参数等于当前用户名 |
| `hasPermission(#id, 'ORDER', 'READ')` | 资源级鉴权 |
| `@securityService.canAccess(#id)` | 调用自定义 Bean 方法 |
| `hasAuthority('admin') and #id > 100` | 组合条件 |

```java
// 实战示例：检查参数归属
@PreAuthorize("#order.userId == authentication.principal.id")
@GetMapping("/orders/{orderId}")
public Order getOrder(@PathVariable Long orderId) { }

// 调用自定义 Service 方法
@PreAuthorize("@rbacService.canAccessProject(#projectId)")
@GetMapping("/projects/{projectId}")
public Project getProject(@PathVariable Long projectId) { }
```

---

## 2.12 安全测试（MockMvc + `@WithMockUser`）

```java
@SpringBootTest
@AutoConfigureMockMvc
class CircleAdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // ✅ 模拟有 ADMIN 角色的用户
    @Test
    @WithMockUser(roles = "ADMIN")
    void adminCanAccessAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/admin/circle/list"))
            .andExpect(status().isOk());
    }

    // ✅ 模拟普通用户 — 期望 403
    @Test
    @WithMockUser(roles = "USER")
    void normalUserCannotAccessAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/admin/circle/list"))
            .andExpect(status().isForbidden());
    }

    // ✅ 模拟未登录 — 期望 401
    @Test
    void unauthenticatedUserGets401() throws Exception {
        mockMvc.perform(get("/api/admin/circle/list"))
            .andExpect(status().isUnauthorized());
    }

    // ✅ 自定义权限的测试注解
    @Test
    @WithMockUser(authorities = "circle:admin:list")
    void userWithSpecificPermissionCanAccess() throws Exception {
        mockMvc.perform(get("/api/admin/circle/list"))
            .andExpect(status().isOk());
    }
    
    // ✅ 测试 @PreAuthorize 注解是否真实生效（防静默失效）
    @Test
    @WithMockUser(authorities = "circle:user:list")  // 无 admin 权限
    void userWithoutPermissionGets403() throws Exception {
        mockMvc.perform(get("/api/admin/circle/list"))
            .andExpect(status().isForbidden());
    }
}
```

**关键测试场景**：

```
☐ 未登录 → 401
☐ 已登录 + 无权限 → 403
☐ 已登录 + 有权限 → 200
☐ 分号绕过（/admin;.js）→ 401 或 403
☐ @PreAuthorize 注解真实生效（不是静默失效）
```

---

## 2.13 Spring Security 5.x → 6.x 迁移对照（补充）

如果你看到 `WebSecurityConfigurerAdapter` 和 `@EnableGlobalMethodSecurity`，说明项目用的是 Spring Security 5.x。以下是两代 API 的关键差异：

### 配置类写法对比

```java
// ── Spring Security 5.x（旧，WebSecurityConfigurerAdapter 已废弃）──
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/public/**").permitAll()
            .antMatchers("/api/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()
            .and()
            .formLogin();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
            .passwordEncoder(passwordEncoder());
    }
}

// ── Spring Security 6.x（新，Lambda DSL + Bean 方式）──
@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // ← 改名了
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth    // ← authorizeHttpRequests
                .requestMatchers("/api/public/**").permitAll()  // ← requestMatchers
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() { ... }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
```

### 关键 API 变更速查

| 功能 | Spring Security 5.x（废弃） | Spring Security 6.x（新） |
|------|------|------|
| 方法安全注解 | `@EnableGlobalMethodSecurity(prePostEnabled=true)` | `@EnableMethodSecurity` |
| 配置基类 | `extends WebSecurityConfigurerAdapter` | 纯 `@Bean` 方式，无需继承 |
| URL 匹配 | `.antMatchers()` | `.requestMatchers()` |
| 授权配置 | `.authorizeRequests()` | `.authorizeHttpRequests()` |
| Lambda 配置 | 可选（链式调用） | 推荐（Lambda DSL） |
| 密码编码器 | `NoOpPasswordEncoder`（默认不强制） | 必须显式声明 `PasswordEncoder` Bean |

### 迁移检查清单

```
☐ 去掉 extends WebSecurityConfigurerAdapter
☐ configure(HttpSecurity) → @Bean SecurityFilterChain
☐ configure(AuthenticationManagerBuilder) → @Bean 方式注入
☐ @EnableGlobalMethodSecurity → @EnableMethodSecurity
☐ .antMatchers() → .requestMatchers()
☐ .authorizeRequests() → .authorizeHttpRequests()
☐ 密码编码器必须显式声明 Bean
☐ 跑一遍 MockMvc 测试确认 @PreAuthorize 仍生效
```

### 你的代码在哪个阶段

```java
// 你现在的代码（Spring Security 5.x）
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    // 这就是 @PreAuthorize 生效的原因 ——
    // prePostEnabled=true 开启了方法级安全，
    // 但不是 @EnableMethodSecurity，而是 @EnableGlobalMethodSecurity
}
```

> **注意**：`securedEnabled=true` 开启的是 `@Secured` 注解（JSR-250），不影响 `@PreAuthorize`。`@PreAuthorize` 只需要 `prePostEnabled=true`。

---

## 总结

Spring Security 的安全问题本质是 **"你以为配了，实际上没配"**：

- `web.ignoring()` 以为是公开路径，实际是"从安全模型中消失"
- `@PreAuthorize` 以为写了就生效，实际需要 `@EnableMethodSecurity`（5.x 是 `@EnableGlobalMethodSecurity(prePostEnabled=true)`）
- `hasRole` 以为匹配权限字符串，实际自动加了 `ROLE_` 前缀
- 过滤器链以为精细规则优先，实际是 `@Order` 靠前的先匹配
- `WebSecurityConfigurerAdapter` 以为还能用，实际 5.7+ 废弃、6.x 删除

---

**系列文章**：
- [概览篇：框架识别、CVE 速查、审计清单](/2026/05/07/java-web-auth-overview/)
- [Apache Shiro 安全配置篇](/2026/05/08/apache-shiro-security-practice/)
- [JWT 认证安全篇](/2026/05/08/jwt-security-practice/)
- [鉴权绕过模式篇](/2026/05/08/java-web-auth-bypass/)
- [会话管理与 Redis 认证篇](/2026/05/08/java-session-redis-auth/)
