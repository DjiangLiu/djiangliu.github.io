# WordPress REST Batch 路由错位漏洞分析

这篇文章讲一个很典型、也很有意思的 WordPress 漏洞链：**一个 batch 子请求的数组错位，最终表现为 pre-auth SQL 注入，并进一步引出后台能力被借用的风险**。

先说结论：

1. 漏洞的根不是单点 SQL 拼接，而是 **REST batch 分发时的请求与 handler 错位**。
2. SQL 注入是真实存在的，但公众号版只讨论其“可读性”和成因，不展开可复现利用细节。
3. 更高危的部分，不在单个 SQL 语句本身，而在于 WordPress 后台能力可能被借用。

![HTTP 无状态但应用有上下文](/images/2026-07-22-wordpress-route-context.svg)

> 先看这张图会更直观：HTTP 不记状态，但 WordPress 会在一次请求里维护 route、current_user、cache、hook 和对象状态。

---

## 一、先说清楚这类问题本质

这类漏洞最核心的，不是某一个 SQL 语句写得不够严，而是 **REST batch 分发、参数校验和运行时状态在同一次请求里发生了错位**。

换句话说，问题不是“HTTP 有状态”，而是 **WordPress 在一次请求里自己维护了很多状态**：

- 当前路由和 handler
- 当前用户
- 对象缓存
- Customizer 上下文
- post 状态转换带来的动态 hook

只要这些状态被串起来，攻击面就不再是单一接口，而是一条链。

---

## 二、源码拆解：四个关键点

### 2.1 batch 错位发生在哪里

`serve_batch_request_v1()` 的逻辑可以概括成两轮：

1. 先把 batch 里的每个子请求解析成 `WP_REST_Request` 或 `WP_Error`
2. 再分别生成 `$matches` 和 `$validation`

源码位置：`wp-includes/rest-api/class-wp-rest-server.php:1712-1866`

关键点在于，解析失败的分支只把错误放进了 `$validation`，没有同步放进 `$matches`。后续 dispatch 又按同一个下标同时读取这三组数组，于是执行对象和验证对象开始错位。

可以把它理解成一个很典型的状态机问题：

- 验证数组记录的是“这个子请求有没有过关”
- 匹配数组记录的是“这个子请求该交给谁”
- 执行阶段却假定这两者永远一一对应

7.0.2 里的修复非常直接，就是在错误分支补上同步 append，让数组重新对齐。

### 2.2 为什么参数校验没挡住

REST 参数不是“进了请求就一定会被处理”。`WP_REST_Request::sanitize_params()` 只会处理当前 route 的 `attributes['args']` 里声明过的参数，未登记的 key 会被直接跳过。

源码位置：

- `wp-includes/rest-api/class-wp-rest-request.php:815-858`
- `wp-includes/rest-api/endpoints/class-wp-rest-posts-controller.php:245-272`
- `wp-includes/rest-api/endpoints/class-wp-rest-posts-controller.php:2995-3011`

这就造成一个很关键的差异：

- item route 只认 item schema
- collection route 才认识集合查询参数

如果 request 在路由和执行阶段发生错位，参数会在“校验视角”里消失，却在“执行视角”里重新出现。

### 2.3 SQL sink 的危险点

真正把问题放大的，是 `WP_Query` 里对作者排除条件的处理方式。

源码位置：`wp-includes/class-wp-query.php:2399-2405`

它的特征是：

- 数组分支会做整数规范化
- 标量分支却只做类型包装和拼接
- 最后进入 SQL 的 `NOT IN (...)` 语义

这种写法的问题不在“有没有转义函数”，而在于 **不同输入形态走了不同的安全策略**。  
7.0.2 改成统一的 ID 列表规范化后，这个差异被收敛了。

### 2.4 为什么说这是“上下文问题”

这条链之所以能一路往下，不是因为 HTTP 有状态，而是因为 **WordPress 在单次请求里维护了很多运行时上下文**。

源码位置：

- `wp-includes/rest-api/class-wp-rest-server.php:1232-1288`
- `wp-includes/class-wp-query.php:3638-3644`
- `wp-includes/class-wp-customize-manager.php:3569-3589`
- `wp-includes/post.php:5815-5883`

这些位置分别说明：

- permission callback 和最终 callback 是在同一个请求对象上连续执行的
- 查询结果会进入当前请求的 post cache
- Customizer 发布时可以临时切换 current_user
- post 状态转换会触发动态 hook

所以漏洞真正被利用的，是 **请求内上下文的连续性**。

---

## 三、为什么会从路由问题演化成 SQL 问题

`/batch/v1` 的设计是把多个子请求放在一次请求中分发。正常情况下，每个子请求都应该按自己的 route、schema 和 permission 独立处理。

但一旦数组状态不同步，就会出现一个很危险的情况：

**验证看到的是 A，执行看到的是 B。**

这时，原本只属于 collection route 的参数，可能被 item route 携带进来；原本会被 schema 拦住的字段，也可能在错位后进入后端查询逻辑。

SQL 问题就发生在这里。  
不是因为 WordPress “忘了转义”，而是因为 **不该进入 SQL 的数据，最后还是进入了 SQL 语义层**。

---

## 四、为什么 HTTP 无状态，还是能被利用

HTTP 的无状态，指的是协议不替你保存上一条请求的业务状态。

但应用层会保存，而且保存得很细：

- `current_user` 会在一次请求里被临时切换
- 查询结果会进入运行期 cache
- post 状态变化会触发动态 hook
- Customizer 会把 changeset 视作一套可被继续消费的上下文

所以，漏洞利用并不需要“跨请求魔法”。  
很多时候，只要在 **同一次请求** 里把这些状态串起来，就足够形成完整利用链。

这也是为什么这类漏洞看起来像“单点输入问题”，实际更像“应用内部状态机被借用”。

---

## 五、7.0.2 为什么能修住

7.0.2 的修复思路其实很一致：

1. 让 batch 的平行状态重新对齐
2. 让查询参数统一走 ID 列表规范化
3. 阻止嵌套 REST 周期再次起一个顶层 dispatch

这三个动作合起来，等于同时切掉：

- 路由错位
- 参数错配
- 请求内上下文复用

所以它不是简单“补一个判断”，而是把链路上的几个关键桥都加了闸。

---

## 六、怎么发现这类问题

公众号版我建议重点看四件事：

1. 有没有 batch、multiplexer、subrequest 这类入口
2. 参数校验和最终执行是不是同一个 handler
3. 标量和数组两种输入形态，是否走了不同的规范化路径
4. 请求内的 cache、user、hook、state 有没有被后续逻辑继续消费

审计时真正要问的是：

**验证的对象，和执行的对象，是不是同一个。**

如果不是，就要高度警惕。

---

## 七、监管视角下更适合怎么讲

如果是公众号发布，建议把重点放在：

- 漏洞成因
- 机制缺陷
- 修复思路
- 审计方法

而把可复现细节、攻击串、命令和具体注入构造都省略掉。

这样读者能看懂问题，也更符合公开平台的表达边界。

如果一定要保留源码分析，建议保留“结构、成因、补丁对照”，不要保留可复现利用链。

---

## 结语

这类漏洞最值得记住的一点是：

**真正危险的，往往不是输入本身，而是输入进入系统后被谁继续消费。**

一旦路由、校验、缓存、状态机和权限上下文连成一条线，单个参数就可能被放大成一条完整攻击链。
