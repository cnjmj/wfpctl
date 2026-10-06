# wfpctl —— Windows 过滤平台 (WFP) 过滤规则管理工具

命令行管理 Windows 过滤平台 (WFP) 过滤规则，**三种语言实现**（C# / Python / C），命令与参数完全一致、规则互通、与系统防火墙隔离。

## 功能

| 命令 | 说明 |
|------|------|
| `add` | 添加过滤规则（放行/阻断、按协议/端口/地址/应用过滤）|
| `del` | 删除规则（按 ID 或 `--name` 按名称）|
| `update` | 修改规则（事务内"删旧+建新"，未指定的保持原值）|
| `list` | 列出规则（`--all` 看系统全部；支持按名称/动作/层/子层筛选）|
| `show` | 查看规则详情（字段中文名、地址 CIDR、配置文件解码、持久化状态）|
| `dump` | 导出规则为 `add` 命令，复制修改即可快速创建新规则 |
| `layers` / `sublayers` | 列出过滤层 / 子层 |
| `sublayer-add` / `sublayer-del` | 添加 / 删除子层 |

## 特性

- **三语言等价实现**：`wfpctl.exe`（C#）、`wfpctl_c.exe`（C）、`wfpctl.py`（Python），命令、参数、输出一致
- **与系统防火墙隔离**：工具规则挂在专属子层，删除不影响系统自带规则
- **可读化输出**：
  - 地址/掩码以 CIDR 显示（`192.168.0.0/16`），地址范围自动合并网段
  - 全部 WFP 条件字段（约 100 个）解析为中文名称，未知字段显示 GUID
  - 配置文件 ID 解码为 `域 / 专用 / 公用`
  - 权重、生效权重、持久化状态（持久 / 临时 / 启动时）一目了然
- **dump 语法导出**：把已有规则（含系统规则）导出为可直接执行的 `add` 命令
- **事务安全**：add/update 均在事务内执行，失败自动回滚
- **多地址条件**：`--rip`/`--lip` 可重复多次（同一规则多条件）
- **启动时间规则**：`--boottime`（BFE 未启动时即生效）

## 快速上手

```cmd
:: 阻断访问某网段
wfpctl add --name "禁访问某网段" --action block --rip 203.0.113.0/24

:: 阻断程序联网
wfpctl add --name "禁程序联网" --action block --app "C:\Program Files\test.exe"

:: 端口范围 + 协议
wfpctl add --name "禁出站80端口" --action block --protocol tcp --lport 80-90

:: 多地址 (匹配任一即生效)
wfpctl add --name "放行内网" --action permit --rip 192.168.0.0/16 --rip 10.0.0.0/8

:: 查看系统全部规则 / 导出某规则为命令
wfpctl list --all
wfpctl dump 12345
```

> 增删规则需以**管理员身份**运行（依赖系统 BFE 服务）。

## 命令一览

```
用法: wfpctl <命令> [选项]

add          添加过滤规则
del          删除过滤规则 (按 ID 或 --name 按名称)
update       修改规则: update <ID> [参数], 未指定的保持原值
list         列出过滤规则 (--all 看系统全部, 默认只看本工具建的)
show         查看规则详情
dump         导出规则为 add 命令: dump <ID> 或 dump --name <关键字>
layers       列出本机所有 WFP 过滤层
sublayers    列出所有子层
sublayer-add 添加子层
sublayer-del 删除子层
help         显示帮助
```

详细参数说明请运行 `wfpctl help`，或查阅 [docs/wfpctl使用手册.html](docs/wfpctl使用手册.html)。

## 编译

**C# 版**（.NET Framework 4.x 自带 csc 即可）：

```cmd
csc /out:wfpctl.exe wfpctl.cs
```

**C 版**（自包含，仅依赖 fwpuclnt.dll 等，用 zig / MinGW 均可）：

```cmd
zig cc -target x86_64-windows-gnu -O2 -o wfpctl_c.exe wfpctl.c -lws2_32
```

**Python 版**：无需编译，`python wfpctl.py help` 即可运行（Python 3.6+，仅标准库 ctypes）。

## 层别名

| 别名 | 说明 |
|------|------|
| `connect-v4/v6` | 出站连接授权 (ALE，推荐) |
| `accept-v4/v6` | 入站连接授权 (ALE，推荐) |
| `out-v4/v6` | 出站传输层（每数据包）|
| `in-v4/v6` | 入站传输层（每数据包）|

## 版本

- v1.8：全量条件字段中文名解析、配置文件 ID 值解码、show 持久化状态
- v1.7：区分系统防火墙规则的持久化提示
- v1.6：show 显示持久化状态
- v1.5：add/update 支持重复地址参数，dump 完整导出多条件
- v1.4：新增 dump 命令
- v1.3：地址显示优化（CIDR / 范围合并）
- v1.2：show 补齐规则 Key、提供者、标志、SDDL 等字段
- v1.1：端口字节序修复（主机字节序）、多子层名称匹配
- v1.0：初始版本
