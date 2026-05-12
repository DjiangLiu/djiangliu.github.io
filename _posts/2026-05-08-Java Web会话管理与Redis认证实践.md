---
layout: post
title: "Java Web 会话管理与 Redis 认证实践"
date: 2026-05-08 18:00:00 +0800
categories: 
  - Java安全
  - Redis
tags: 
  - Session管理
  - Redis
  - 会话安全
  - 认证授权
  - 分布式会话
  - 代码审计
series: Java Web 认证授权安全系列
series_order: 6
---

# Java Web 会话管理与 Redis 认证实践

会话管理是认证体系的"最后一公里"。无论前端用 JWT 还是 Session，服务端的校验逻辑、Redis 缓存策略、并发控制直接决定了整个认证链路的安全性。

> 本文是 [Java Web 认证授权安全系列](/2026/05/07/java-web-auth-overview/) 的第六篇。

---

## 6.1 Session Fixation 攻击

```java
// ❌ 登录前后 Session ID 不变
http.sessionManagement().sessionFixation().none();

// ✅ 登录后更换 Session ID
http.sessionManagement()
    .sessionFixation().migrateSession();  // 创建新 Session，复制属性
// 或
http.sessionManagement()
    .sessionFixation().newSession();      // 创建全新 Session
```

---

## 6.2 Cookie 安全属性

```java
@Bean
public CookieSerializer cookieSerializer() {
    DefaultCookieSerializer serializer = new DefaultCookieSerializer();
    serializer.setSameSite("Strict");
    serializer.setUseSecureCookie(true);
    serializer.setUseHttpOnlyCookie(true);
    return serializer;
}
```

```yaml
server:
  servlet:
    session:
      cookie:
        http-only: true
        secure: true
        same-site: strict
      timeout: 30m
```

---

## 6.3 服务端 Session 校验的正确模式

### 模式 A：仅判空（不安全）

```java
// ❌ 只判断 getAttribute 是否为 null，无状态校验
Object user = session.getAttribute("user");
if (user == null) { response.sendRedirect("/login"); return false; }
return true;  // 不管 user 是否已被禁用、IP 是否变化
```

### 模式 B：Redis 集中校验（推荐）

```java
@Component
public class SessionAuthInterceptor implements HandlerInterceptor {
    @Autowired private RedisTemplate<String, SessionUser> redis;
    @Autowired private UserService userService;
    
    public boolean preHandle(HttpServletRequest request, ...) {
        String sessionId = request.getHeader("X-Session-Id");
        if (sessionId == null) {
            HttpSession s = request.getSession(false);
            if (s == null) { respond401(response, "未登录"); return false; }
            sessionId = s.getId();
        }
        
        SessionUser user = redis.opsForValue().get("session:user:" + sessionId);
        if (user == null) { respond401(response, "Session 过期"); return false; }
        
        // 检查用户是否仍有效（可能被管理员禁用）
        if (!userService.isUserActive(user.getUserId())) {
            redis.delete("session:user:" + sessionId);
            respond401(response, "账号已禁用"); return false;
        }
        
        // 检查 IP 变化（管理后台推荐严格模式）
        String currentIp = getClientIp(request);
        if (!currentIp.equals(user.getLoginIp())) {
            log.warn("IP变化: userId={}", user.getUserId());
        }
        
        // 续期
        redis.expire("session:user:" + sessionId, Duration.ofMinutes(30));
        request.setAttribute("currentUser", user);
        return true;
    }
}
```

```java
@Data
public class SessionUser implements Serializable {
    private Long userId;
    private String username;
    private Set<String> roles;
    private Set<String> permissions;
    private String loginIp;
    private String userAgent;
    private LocalDateTime loginTime;
}
```

### 模式 C：无状态 Token + Redis 黑名单

```java
@Override
public boolean preHandle(HttpServletRequest request, ...) {
    String token = extractBearerToken(request);
    if (token == null) { respond401(response, "缺少Token"); return false; }
    
    // 黑名单检查（已注销的 Token）
    if (Boolean.TRUE.equals(redis.hasKey("token:blacklist:" + getTokenId(token)))) {
        respond401(response, "Token 已失效"); return false;
    }
    
    // JWT 校验
    try {
        TokenUser user = jwtService.validateAndParse(token);
        request.setAttribute("currentUser", user);
        return true;
    } catch (JwtException e) {
        respond401(response, "Token 无效"); return false;
    }
}
```

---

## 6.4 Redis 权限缓存的安全陷阱

```java
// ❌ 缓存无失效机制 — 权限变更后旧权限仍生效
public Set<String> getUserPermissions(Long userId) {
    Set<String> cached = redis.opsForValue().get("perm:" + userId);
    if (cached != null) return cached;  // ← 永远返回缓存
    // ...
}

// ✅ 变更时主动失效 + 短 TTL
public void updateUserPermissions(Long userId, Set<String> newPerms) {
    permissionMapper.updatePermissions(userId, newPerms);
    redis.delete("perm:" + userId);  // 立即失效
    redis.convertAndSend("perm:invalidate", userId.toString());  // 通知其他节点
}

public Set<String> getUserPermissions(Long userId) {
    return Optional.ofNullable(redis.opsForValue().get("perm:" + userId))
        .orElseGet(() -> {
            Set<String> perms = permissionMapper.findByUserId(userId);
            redis.opsForValue().set("perm:" + userId, perms, Duration.ofMinutes(5));
            return perms;
        });
}
```

---

## 6.5 并发登录控制

```java
@Component
public class SessionManager {
    @Autowired private RedisTemplate<String, String> redis;
    
    public void registerSession(Long userId, String newSessionId) {
        String oldSessionId = redis.opsForValue().get("user:session:" + userId);
        if (oldSessionId != null && !oldSessionId.equals(newSessionId)) {
            redis.opsForValue().set("session:blacklist:" + oldSessionId, "kicked", 
                Duration.ofMinutes(30));
            log.info("用户 {} 新设备登录，旧 Session 被踢出", userId);
        }
        redis.opsForValue().set("user:session:" + userId, newSessionId, 
            Duration.ofHours(2));
    }
}
```

---

## 6.6 暴力破解防护（Redis 限流）

```java
@Component
public class LoginRateLimiter {
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(5);
    private static final Duration BLOCK = Duration.ofMinutes(15);
    
    public boolean isBlocked(String username, String ip) {
        return Boolean.TRUE.equals(redis.hasKey("login:block:" + ip))
            || Boolean.TRUE.equals(redis.hasKey("login:block:user:" + username));
    }
    
    public void recordFailedAttempt(String username, String ip) {
        String key = "login:attempt:" + ip + ":" + username;
        Long attempts = redis.opsForValue().increment(key);
        if (attempts == 1) redis.expire(key, WINDOW);
        if (attempts >= MAX_ATTEMPTS) {
            redis.opsForValue().set("login:block:" + ip, 1, BLOCK);
            redis.opsForValue().set("login:block:user:" + username, 1, BLOCK);
        }
    }
}
```

---

## 6.7 混合认证架构设计

```
管理后台 (Web/Cookie) ──→ Session 认证 ──┐
                                          ├──→ Redis 统一存储
移动端/API (Token)    ──→ JWT 认证    ──┘
```

```java
// 管理后台：Session
@Bean
public SecurityFilterChain webChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/admin/**")
        .authorizeHttpRequests(a -> a.anyRequest().hasRole("ADMIN"))
        .formLogin(Customizer.withDefaults())
        .sessionManagement(s -> s.sessionCreationPolicy(IF_REQUIRED));
    return http.build();
}

// API：JWT
@Bean @Order(1)
public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
    http.securityMatcher("/api/**")
        .authorizeHttpRequests(a -> a.requestMatchers("/api/public/**").permitAll()
            .anyRequest().authenticated())
        .oauth2ResourceServer(o -> o.jwt(Customizer.withDefaults()))
        .sessionManagement(s -> s.sessionCreationPolicy(STATELESS));
    return http.build();
}
```

| 问题 | Session | JWT | 混合方案 |
|------|:--:|:--:|:--:|
| 吊销 | ✅ | ❌ | Redis 黑名单 |
| 扩展 | ❌ | ✅ | Redis 共享 |
| CSRF | ❌ | ✅ | SameSite Cookie |
| XSS | ✅ | ❌ | 管理后台用 Session |

---

## 6.8 Spring Session 深度配置（补充）

```java
@Configuration
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 1800)
public class SessionConfig {

    @Bean
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        // 不要用 JdkSerializationRedisSerializer — 有反序列化风险
        // 推荐 Jackson 或 GenericJackson2JsonRedisSerializer
        return new GenericJackson2JsonRedisSerializer();
    }

    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        serializer.setCookieName("SESSIONID");
        serializer.setCookiePath("/");
        serializer.setDomainNamePattern("^.+?\\.(example\\.com)$");
        serializer.setUseSecureCookie(true);
        serializer.setUseHttpOnlyCookie(true);
        serializer.setSameSite("Lax");
        return serializer;
    }

    @Bean
    public RedisIndexedSessionRepository sessionRepository(
            RedisOperations<String, Object> redis) {
        RedisIndexedSessionRepository repo = 
            new RedisIndexedSessionRepository(redis);
        repo.setDefaultMaxInactiveInterval(Duration.ofMinutes(30));
        
        // 关键：配置 Redis key 前缀，方便管理
        repo.setRedisKeyNamespace("myapp:session:");
        
        return repo;
    }
}
```

**Spring Session 安全注意事项**：

1. **序列化器选择**：避免 `JdkSerializationRedisSerializer`，它和 Java 原生反序列化一样存在 RCE 风险
2. **Redis 密码**：生产环境 `spring.redis.password` 必须设置
3. **命名空间隔离**：不同应用使用不同的 `redisKeyNamespace`，避免 Session 混淆
4. **findByPrincipalName**：此方法会遍历所有 Session key（`KEYS *`），大数据量时性能极差，谨慎使用

---

## 6.9 Redis Cluster 模式下的认证（补充）

```yaml
# Redis Cluster 配置
spring:
  redis:
    cluster:
      nodes:
        - 10.0.1.10:6379
        - 10.0.1.11:6379
        - 10.0.1.12:6379
    password: ${REDIS_PASSWORD}  # 必须从环境变量读取
    timeout: 3000ms
    lettuce:
      pool:
        max-active: 50
        max-idle: 20
        min-idle: 5
```

**Cluster 模式下的 Session 一致性陷阱**：

```
问题：Spring Session 默认使用 Redis key 存储
Cluster 模式下 key 会被 hash 到不同分片
但 Session 相关的原子操作（如 find/findByPrincipalName）
跨分片时无法保证事务性

解决：
1. 使用 HashTag 绑定会话相关 key 到同一分片
   repo.setRedisKeyNamespace("{myapp}:session:")
2. 或使用单节点 Redis 存储 Session（小规模推荐）
```

---

## 6.10 WebSocket 会话安全（补充）

WebSocket 连接建立后的认证是一个容易被忽略的问题：

```java
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketSecurityConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureClientInboundChannel(ChannelRegistration registration) {
        registration.interceptors(new ChannelInterceptor() {
            @Override
            public Message<?> preSend(Message<?> message, MessageChannel channel) {
                StompHeaderAccessor accessor = 
                    MessageHeaderAccessor.getAccessor(message, StompHeaderAccessor.class);
                
                if (StompCommand.CONNECT.equals(accessor.getCommand())) {
                    // 从 STOMP CONNECT 帧中提取 Token
                    String token = accessor.getFirstNativeHeader("Authorization");
                    if (token == null || !token.startsWith("Bearer ")) {
                        throw new AccessDeniedException("未认证");
                    }
                    
                    // 验证 Token 并设置用户
                    User user = tokenService.validateAndGetUser(token.substring(7));
                    accessor.setUser(user);
                }
                
                // 对于 SUBSCRIBE/SEND 等命令，检查权限
                if (StompCommand.SUBSCRIBE.equals(accessor.getCommand())) {
                    String destination = accessor.getDestination();
                    User user = (User) accessor.getUser();
                    
                    // 检查用户是否有权限订阅此主题
                    if (destination.startsWith("/topic/admin/") 
                        && !user.hasRole("ADMIN")) {
                        throw new AccessDeniedException("无权限订阅此主题");
                    }
                }
                
                return message;
            }
        });
    }
}
```

**WebSocket 安全检查清单**：

```
☐ CONNECT 帧必须验证 Token/Cookie
☐ SUBSCRIBE 主题需要权限检查（/topic/admin/ 仅管理员）
☐ SEND 目标需要校验（防止向他人主题发送消息）
☐ 心跳超时断开（防止资源耗尽）
☐ 单个用户最大连接数限制
☐ 消息大小限制（防止 DoS）
```

---

## 总结

会话管理的安全本质是回答三个问题：

1. **你是谁？** — 认证：Session/Token 是否有效
2. **你还应该是你吗？** — 会话完整性：IP/UA 是否变化，是否被踢出
3. **你能做什么？** — 授权：Session 中的权限是否仍有效，缓存是否实时

Redis 在其中的角色是**共享的真实状态源**——无论前端使用 Session 还是 JWT，服务端都需要一个地方存储"当前有效的会话/权限/黑名单"信息。Redis 配置的安全性直接决定了这层防护是否可靠。

---

**系列文章**：
- [概览篇](/2026/05/07/java-web-auth-overview/)
- [Spring Security 安全配置篇](/2026/05/08/spring-security-security-practice/)
- [Apache Shiro 安全配置篇](/2026/05/08/apache-shiro-security-practice/)
- [JWT 认证安全篇](/2026/05/08/jwt-security-practice/)
- [鉴权绕过模式篇](/2026/05/08/java-web-auth-bypass/)
