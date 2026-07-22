---
layout: post
title: "WordPress REST batch 路由错位到 wp2shell：一次 pre-auth SQLi/RCE 链路深度分析"
date: 2026-07-22 10:00:00 +0800
categories:
  - 安全分析
  - WordPress
tags:
  - WordPress
  - REST API
  - SQL注入
  - 路由错位
  - wp2shell
  - 代码审计
  - 漏洞分析
author: test404
---

# WordPress REST batch 路由错位到 wp2shell：一次 pre-auth SQLi/RCE 链路深度分析

> 说明：本文基于本地 WordPress 7.0.1 源码与 `wp2shell-poc` 还原，重点分析漏洞为什么出现、PoC 如何运行、为什么 blind SQLi 不等于 getshell，以及 7.0.2 做了哪些修复。

---

## 1. 先给结论

这不是一个单纯的 SQL 注入漏洞，而是一条完整的组合链：

1. `WP_REST_Server::serve_batch_request_v1()` 的数组错位造成 route confusion
2. 错位后的请求把 item route 的 query 参数送进 collection handler
3. `author_exclude -> author__not_in` 落到 `WP_Query` 的 SQL 拼接点
4. PoC 通过 blind / error / UNION 三种方式读库
5. UNION 伪造 `WP_Post` 后，进一步借 WordPress 的对象缓存、oEmbed、Customizer、动态 hook 和正常后台上传路径完成 getshell

也就是说：

**blind SQLi 负责“读”，UNION 负责“快读”，getshell 依赖的是后续的 WordPress 状态机桥接。**

![HTTP 无状态但应用有上下文](/images/2026-07-22-wordpress-route-context.svg)

> 这张图把“HTTP 无状态”和“应用层上下文”分开看：真正被利用的不是协议，而是 WordPress 在单次请求里维护的运行时状态。

---

## 2. PoC 的程序结构

PoC 入口很清晰：

- `wp2shell.py` 和 `wp2shell/__main__.py` 只是启动器
- `cli.py` 提供 `check/read/shell`
- `client.py` 负责构造 nested batch payload
- `sqli.py` 负责 blind / error / UNION 读取
- `exploit.py` 负责 SQLi-to-admin bridge
- `shell.py` 负责登录、上传插件 webshell、执行命令

从设计上看，它不是“单个 payload 工具”，而是三段式：

1. 可达性和路由错位确认
2. SQLi 读库
3. SQLi-to-admin 到 shell

---

## 3. 漏洞根因：batch 处理时的状态不同步

`/batch/v1` 的处理器在解析每个子请求后，会维护三组平行状态：

- `$requests`
- `$matches`
- `$validation`

7.0.1 的问题在于，解析失败的子请求只进了 `$requests` 和 `$validation`，没有进 `$matches`。

后续 dispatch 时又按同一个 `$i` 同时读取三组数组，于是出现错位：

- 第 i 个请求的验证结果，可能被第 i+1 个请求的 handler 使用
- 最终执行的 callback，不一定对应原始 path

补丁在 7.0.2 里非常直接：错误分支也同步 append `$matches[] = $single_request`。

---

## 4. PoC 为什么要嵌套 batch

PoC 的 `client.py` 里有一颗专门的“错位种子”：

`_DESYNC_PRIMER = {"method": "POST", "path": "///"}`

这个 path 的作用不是访问任何网络资源，而是让 `wp_parse_url()` 失败，制造 `WP_Error`，从而打乱平行数组。

### 第一层错位

PoC 把一个 `POST /wp/v2/posts` 包进 outer batch。

这个请求在 validation 阶段看起来是 posts 请求，但 dispatch 时可能被当成 batch handler 执行，于是 `body.requests` 不再受 batch schema 的 method 限制。

### 第二层错位

再在 inner batch 里放：

`GET /wp/v2/posts/999999?author_exclude=...`

这个 path 先按 item route 校验，item route schema 不认识 `author_exclude`；但错位后，它会被 posts collection handler 的 `get_items()` 消费。

---

## 5. SQLi 从哪里进入

posts controller 的映射关系如下：

- `author_exclude` -> `author__not_in`
- `exclude` -> `post__not_in`
- `parent_exclude` -> `post_parent__not_in`

问题在 `WP_Query`：

```php
if ( ! empty( $query_vars['author__not_in'] ) ) {
    if ( is_array( $query_vars['author__not_in'] ) ) {
        $query_vars['author__not_in'] = array_unique( array_map( 'absint', $query_vars['author__not_in'] ) );
        sort( $query_vars['author__not_in'] );
    }
    $author__not_in = implode( ',', (array) $query_vars['author__not_in'] );
    $where .= " AND {$wpdb->posts}.post_author NOT IN ($author__not_in) ";
}
```

只清洗 array，不清洗 scalar。  
而 REST 这边又因为 route confusion 把本不该出现的参数放进来了。

所以 SQLi 的本质是：

**schema gap + handler confusion + scalar 拼接 sink**

---

## 6. 盲注、错误回显和 UNION 的分工

`sqli.py` 提供了三种 extractor。

### 6.1 BlindSQLi

通过 `0) OR SLEEP(n)-- -` 做时间确认，通过 `-1) AND (<condition>)-- -` 做布尔真/假判断。

这里的关键 oracle 不是响应 body，而是 `X-WP-Total`。

为什么？

因为这条链打到的是 posts collection，`WP_REST_Controller` 会把 `WP_Query->found_posts` 放进响应头。

### 6.2 ErrorBasedSQLi

当目标暴露 MySQL 错误时，PoC 通过 `EXTRACTVALUE()` / `UPDATEXML()` 走 error-based 读取。

这条路径更快，但依赖环境。

### 6.3 UnionSQLi

`UnionSQLi` 伪造一整行 `wp_posts`，把表达式值放进 `post_title`。

它之所以能成立，是因为 PoC 还额外做了两件事：

- `orderby=none`，避免全局 `ORDER BY` 破坏 UNION
- `per_page=500`，尽量让结果保持完整行模式

这一步不是为了写入数据库，而是为了让 WordPress 运行时接受一条“假的 post row”。

---

## 7. 为什么 UNION 行还能影响后续逻辑

这里最容易被误解。

PoC 并不是只想把值显示出来，它更关心的是：

1. 这条假行能否被 `get_post()` 接受
2. 这条假行会不会被放进当前请求的 post cache
3. 这条假行能否继续参与 oEmbed / Customizer / menu item 的处理链

WordPress 的 `WP_Query` 在结果集上会调用 `update_post_caches()` 和 `_prime_post_caches()`，底层会把对象放进运行期 cache。

而 `update_post_cache()` 甚至会把 `WP_Post` 规范化后塞进 `wp_cache_add_multiple( ..., 'posts' )`。

所以，PoC 的“假对象”在这个请求里并不只是字符串，它会成为一个可被后续代码消费的运行时对象。

---

## 8. SQLi 怎么桥到管理员创建

这条链的后半段是 WordPress 内部机制的组合拳。

### 8.1 先种 oEmbed cache

`WP_Embed` 在处理 `[embed]` 时，会根据 URL 生成缓存；在某些路径下，会直接创建 `oembed_cache` post。

PoC 利用 UNION 伪造的 post 去触发这一步，然后再用 SQL 读出真实的 `oembed_cache` post ID。

### 8.2 再构造 Customizer / Menu Item / Request 形状

PoC 把若干真实 post ID 重新安排成一条“对象图”：

- `customize_changeset`
- `nav_menu_item`
- `request`
- `future`
- `draft`

这些字段不是为了好看，而是为了触发 WordPress 在 `transition_post_status` 里挂的默认行为。

### 8.3 利用动态 hook 触发 parse_request

`wp_transition_post_status()` 会拼出动态 hook：

`{$new_status}_{$post->post_type}`

当 `new_status = parse`、`post_type = request` 时，就会形成 `parse_request`。

WordPress 的 REST bootstrap 正是挂在 `parse_request` 上的：

`add_action( 'parse_request', 'rest_api_loaded' );`

这就解释了为什么 PoC 能在同一次请求中把一个看似普通的 post/status 转换，变成 REST 再入场。

### 8.4 临时管理员上下文

`WP_Customize_Manager::_publish_changeset_values()` 会在保存某些 setting 时临时切换当前用户：

`wp_set_current_user( $setting_user_ids[ $setting_id ] )`

PoC 正是利用这个“按 setting 用户切换上下文”的机制，把后续 REST 创建用户请求放进管理员身份里执行。

---

## 9. getshell 是怎么落地的

`WP_REST_Users_Controller::create_item_permissions_check()` 需要 `current_user_can( 'create_users' )`。

一旦前面的桥把当前用户切成了管理员，这个限制就自然通过。

然后 PoC 登录这个新管理员，走后台插件上传：

- `plugin-install.php?tab=upload`
- `update.php?action=upload-plugin`

上传接口本身要求 nonce 和 `upload_plugins` capability，因此这里已经不是 pre-auth 了，而是一个标准后台管理动作。

PoC 只是把这个动作自动化了，并把插件里的 webshell 做成随机路径和 token 防护，避免一落地就裸露。

---

## 10. 7.0.2 的修复为什么足够关键

7.0.2 的修复不是一刀，而是三刀一起下：

1. `serve_batch_request_v1()` 的错位修正
2. `author__not_in` 的 ID 列表规范化
3. `serve_request()` / `rest_api_loaded()` 的嵌套 REST 周期阻断

这意味着：

- route confusion 先被掐掉
- SQL sink 的标量入口被清洗掉
- 嵌套 dispatch 的桥也被关掉

所以 `git checkout 7.0.2` 之后，这条 PoC 链整体上就断了，不是“换个 payload 还能绕过去”的那种单点修补。

---

## 11. 这种问题为什么容易漏

因为它不是单个函数的 bug，而是三个层面叠在一起：

1. **分发层**：请求和 handler 错位
2. **参数层**：schema A 校验，handler B 消费
3. **数据层**：array 分支清洗，scalar 分支拼接

如果只做 SQL 审计，你会看到 `NOT IN (...)`。  
如果只做 REST 审计，你会看到 batch 分发。  
真正的漏洞出现在中间那层“本不该传过去的数据，最后还是传过去了”。

---

## 12. 如何审计同类问题

我建议把 WordPress REST 审计分成四步：

### 12.1 先找分发器

搜所有：

```bash
rg -n "serve_batch_request|batch|match_request_to_handler|respond_to_request|allow_batch|dispatch\\("
```

重点看：

- 请求数组是否每个分支都同步 append
- 校验、权限、执行是否属于同一个 request
- 有没有 top-level REST 递归进入的可能

### 12.2 再找参数映射

```bash
rg -n "register_rest_route|permission_callback|callback|args|allow_batch"
```

重点看：

- item route 和 collection route 是否共享参数
- 未注册参数是否会被静默丢弃
- 同一个参数在不同 handler 下语义是否变化

### 12.3 再找 SQL sink

```bash
rg -n "NOT IN \\(|IN \\(|author__not_in|post__not_in|post_parent__not_in|__not_in|implode\\(.*\\(array\\)"
```

重点看：

- `is_array()` 分支和 scalar 分支是否一致
- 是否存在 `(array)` 包装后直接拼接
- 是否遗漏 `wp_parse_id_list()` / `absint()`

### 12.4 最后找状态机桥

```bash
rg -n "wp_cache_add_multiple|update_post_cache|_prime_post_caches|get_post\\(|wp_set_current_user|transition_post_status|parse_request"
```

重点看：

- 假对象能否进入缓存
- 动态 hook 能否触发意外状态切换
- 运行时当前用户是否会被临时替换

---

## 13. 适合写进 skill 的审计规则

如果要把这类问题长期固化进 skill，我会把规则写成三句：

1. **验证的 route 和执行的 route 必须是同一个。**
2. **数组/标量分支必须共享同一套规范化逻辑。**
3. **任何 request-local 假对象进入 cache 后，都要检查它能否影响后续权限、hook 和状态转换。**

---

## 14. 总结

这个漏洞最危险的地方，不在于 SQL 拼接本身，而在于它把 WordPress 的几层“看起来都合理”的机制连成了一条攻击链：

- batch 分发
- schema 校验
- query var 映射
- SQL 拼接
- 对象缓存
- oEmbed 缓存
- Customizer 发布
- 动态 hook
- 后台用户创建
- 插件上传

单看每一层都像正常功能，连起来才是漏洞。

这也是为什么它值得单独写一篇深度分析：它不是一个点，而是一条链。
