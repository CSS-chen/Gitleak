# gitleak

> 高性能、高并发的 `.git` 泄露检测与仓库恢复工具。单文件 Go 程序，零第三方依赖。

`gitleak` 面向现代环境重写：Go 1.21+ 编译为单个可执行文件，原生支持 HTTP/2、代理、TLS、
Windows / Linux / macOS，内置连接池 + 全局/单主机并发控制 + 令牌桶限速，用 goroutine 池
并发探测与下载对象。相对于依赖已废弃运行时（Python 2、旧版 Ruby、旧版 .NET）的旧工具，
本工具无需安装运行时，开箱即用。

## 免责声明

本工具仅用于**已获得授权**的安全测试、资产自查与应急响应。使用前请确认你对目标系统拥有
明确的书面授权。未经授权访问他人系统与数据在大多数司法管辖区属于违法行为，作者不承担
任何滥用导致的后果。

## 功能

- **检测**：`.git/HEAD`、`.git/config`、`.git/index`、`.git/logs/HEAD`、`.git/packed-refs`、
  `.git/objects/info/packs` 多路径联合判定，识别软 404 与假 HEAD 陷阱。
- **恢复工作区**：优先使用对象库直接还原 HEAD 树（含索引加速），索引被禁时自动回退到
  逐个读取树对象，最终按 blob 下载还原全部文件，保持目录结构、可执行位与符号链接。
- **打包对象支持**：解析 `objects/info/packs` + 下载 `.idx` / `.pack`，支持 v1/v2 索引、
  OFS_DELTA / REF_DELTA 增量对象，packed-only 仓库（没有松散对象）也能直接恢复。
- **历史下载**：`--history` 沿提交/树/blob 遍历全部历史对象；`--all-branches` 跟随所有 ref。
- **`--write-git`**：落地一个可直接使用的 `.git`（objects、refs、HEAD、config、index），
  之后可以 `git log` / `git status` / `git checkout` 继续分析。
- **stash 恢复**：自动探测泄露的 `.git/refs/stash`，把 stash 树额外还原到 `.gitleak-stash/`；
  `--write-git` 时同时写回 `refs/stash` 与 reflog，可直接 `git stash list` / `git show refs/stash`。
  stash 常保存从未进入任何分支、甚至已被删除的敏感内容。
- **凭据扫描**：`--scan-secrets` 对恢复出的文件做正则扫描（AWS / GitHub / Slack / Google /
  Stripe / JWT / 私钥 / 硬编码口令等）。
- **附加泄露探测**：`--extra` 检查 `.svn`、`.hg`、`.env`、`.DS_Store` 等。
- **批量扫描**：命令行参数或 `-l` 列表文件混合输入，JSON 报告汇总，确定性输出目录名。

## 安装 / 构建

需要 Go 1.21 或更高版本：

```sh
go build -o gitleak .
# 交叉编译示例
GOOS=linux   GOARCH=amd64 go build -o gitleak-linux .
GOOS=windows GOARCH=amd64 go build -o gitleak.exe .
```

Windows 上如果默认缓存目录不可写，可显式指定：

```powershell
$env:GOCACHE="C:\temp\gocache"; $env:GOTMPDIR="C:\temp\gotmp"; go build -o gitleak.exe .
```

## 快速开始

```sh
# 检测单个目标（不下载，只看是否暴露 .git）
./gitleak scan https://example.com/.git/

# 批量检测（列表文件，每行一个 URL，# 为注释）
./gitleak scan -l targets.txt -o out --json out/report.json

# 下载并恢复工作区文件
./gitleak dump https://example.com/ -o dump

# 下载完整历史并还原为可用的 git 仓库（自动包含泄露的 stash）
./gitleak dump https://example.com/ --history --all-branches --write-git -o dump

# 检测 + 自动恢复，并扫描凭据
./gitleak auto -l targets.txt -o out --scan-secrets --json out/report.json
```

未写协议的输入默认按 `https://` 处理；会自动去除末尾 `/`、`/.git`、`/.git/HEAD` 等后缀。

## 子命令

| 子命令 | 说明 | 退出码 |
| --- | --- | --- |
| `scan <url...>` | 仅检测哪些目标暴露 `.git`，可选 `--json` 报告 | 0=发现漏洞，2=未发现，3=错误 |
| `dump <url>` | 检测并恢复**单个**目标（必须恰好 1 个） | 0=恢复成功，2=未发现，3=恢复失败 |
| `auto <url...>` | 先批量检测，再对存在漏洞的目标自动执行 dump | 0=成功，2=全部无漏洞，3=有漏洞但恢复失败 |
| `version` | 打印版本号 | 0 |
| `help` | 打印帮助 | 0 |

`-l/--list` 文件每行一个目标，忽略空行与 `#` 开头的注释行；`-` 表示从 stdin 读取。

## 常用选项

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `-l, --list FILE` | | 从文件读取目标列表（`-` 为 stdin） |
| `-o, --out DIR` | `gitleak-out` | 输出根目录 |
| `--json FILE` | | 写出 JSON 报告 |
| `-c, --concurrency N` | 64 | 全局并发请求上限 |
| `--per-host N` | 8 | 单主机并发请求上限 |
| `--rate N` | 0（不限） | 全局请求速率（令牌桶，每秒） |
| `-t, --timeout D` | `10s` | 单请求超时 |
| `--retries N` | 3 | 单请求重试次数（指数退避 + 抖动，尊重 Retry-After） |
| `-A, --user-agent UA` | `gitleak/1.1.0` | User-Agent |
| `-H, --header K:V` | | 附加请求头，可重复 |
| `--proxy URL` | | `http://`、`https://`、`socks5://`、`socks5h://` 代理 |
| `-k, --insecure` | | 跳过 TLS 证书校验 |
| `--max-body MB` | 64 | 单响应体上限 |
| `--threads N` | 32 | 下载/恢复工作协程数 |
| `--history` | | 下载完整历史 |
| `--all-branches` | | 历史下载时跟随所有 ref |
| `--write-git` | | 写出可用 `.git`（隐含 `--history`） |
| `--resume` | | 复用缓存对象（`<out>/.gitleak-cache/`） |
| `--scan-secrets` | | 恢复后扫描凭据 |
| `--extra` | | 额外泄露路径探测 |
| `--no-extract` | | 只检测，不下载 |
| `--max-pack MB` | 1024 | packfile 大小上限 |
| `--max-objects N` | 200000 | 历史对象数量上限 |
| `--debug` / `--quiet` / `--no-color` | | 调试输出 / 静默 / 关闭 ANSI 颜色 |

## 输出结构

```text
gitleak-out/
└── example.com_1a2b3c4d/          # 目标 slug：主机+路径 + root 的 sha1 前 8 位（确定性）
    ├── ...                        # 恢复出的工作区文件（普通 dump）
    ├── .git/                      # --write-git 时生成的可直接使用的仓库
    ├── .gitleak-stash/            # 从 refs/stash 恢复的文件（若目标暴露 stash）
    └── .gitleak-cache/            # 仅 --resume 的缓存（位于恢复树之外）
```

扫描结果的 `out_dir` 同样按确定性 slug 生成，便于对照与去重。

## JSON 报告

```json
{
  "tool": "gitleak",
  "version": "1.1.0",
  "generated_at": "2026-11-02T12:00:00Z",
  "targets": [
    {
      "input": "https://example.com/.git/",
      "root": "https://example.com/",
      "vulnerable": true,
      "score": 60,
      "soft_404": false,
      "head_ref": "refs/heads/main",
      "head_commit": "0123abcd...",
      "remote": "https://example.com/secret/repo.git",
      "files_restored": 140,
      "bytes": 204283,
      "out_dir": "gitleak-out/example.com_1a2b3c4d",
      "stash_commit": "51790fbc...",
      "stash_files": 3,
      "missing": [],
      "warnings": [],
      "files": [{"path": "README.md", "sha1": "...", "mode": "100644", "bytes": 42}],
      "secrets": [],
      "error": "",
      "elapsed_ms": 1234
    }
  ]
}
```

所有目标字段始终存在；`missing` 与 `warnings` 为数组，永不为 `null`。

## 退出码

| 码 | 含义 |
| --- | --- |
| 0 | 成功：发现漏洞 / 成功恢复 |
| 1 | 用法错误（缺目标、未知子命令、参数非法） |
| 2 | 未发现漏洞（软 404、假 HEAD、正常站点） |
| 3 | 运行期失败（网络、写盘、恢复 0 个文件等） |

## 高性能 / 高并发设计

- **单二进制**：纯 Go 标准库，无运行时依赖，便于在新系统与隔离环境落地。
- **连接复用**：`http.Transport` 连接池 + keep-alive + HTTP/2（`ForceAttemptHTTP2`），
  避免每请求重新握手；默认 64 全局并发 / 8 单主机并发，避免把目标打挂。
- **精确限速**：全局令牌桶（`--rate`），配合 `Retry-After` 与指数退避 + 抖动重试，
  在贴近真实客户端行为的前提下尽量提高吞吐。
- **分层并发**：探测阶段多目标并发；对象下载使用 worker 池 + 去重队列（同一对象只下载一次）；
  树遍历使用 BFS 分批（512 个对象一批）流水线，下载与解析重叠进行。
- **本地优先**：松散对象下载后写入本地缓存，`--resume` 时命中缓存直接跳过网络；
  packfile 解析带 singleflight，同一增量对象链只解压一次。
- **内存安全**：对象大小、响应体、packfile、增量深度、恢复文件数均有上限；
  路径经过安全清洗，拒绝 `..` / 绝对路径，避免恶意仓库写出目录。
- **可中断**：`Ctrl+C` / SIGTERM 优雅取消，已下载文件保留。

## 目录结构

```text
.
├── main.go                # 入口
├── internal/cli/          # 参数解析、子命令、退出码
├── internal/app/          # 检测、对象获取、历史、恢复、凭据扫描、报告
├── internal/gitx/         # 松散对象、索引 v2/v3/v4、树/提交/标签、idx/pack 解析
├── internal/httpc/        # HTTP 客户端：并发、重试、限速、代理、统计
├── internal/ui/           # 终端输出与进度
└── tests/                 # 端到端测试（本地 git fixture + 回环 HTTP 服务器）
```

## 测试

```sh
go vet ./...
go test ./...
python tests/run_e2e.py     # 端到端：真实 git 仓库 + 本地回环 HTTP 服务
```

## 实战验证

在授权测试环境中对真实 CTF 靶场（CTFHub .git 泄露题）实测：

- 检测：0.65 s、4 个请求判定暴露，定位 HEAD 为 refs/heads/master / d66a4399。
- 工作区恢复：0.97 s 还原 2 个文件（637 B）。
- 历史恢复：--history --all-branches --write-git 1.57 s 拉取 3 个提交、8 个对象，
  生成可直接 git log / git fsck 的仓库；flag 内容 ctfhub{f56bad8ff2e10f4f86ae8c03}
  即从恢复的提交历史（含被 git reset 丢弃、仍保留在 reflog 中的 remove flag 提交）
  中提取，证据仓库保留在 live-history/。
- stash 泄露：另一授权靶场（CTFHub .git 泄露 / stash 变体）检测 0.48 s、4 个请求；
  `dump --history --all-branches --write-git` 自动探测到 `refs/stash`（51790fbc...），
  历史从 3 个提交 / 8 个对象扩展到 5 个提交 / 12 个对象，flag
  `ctfhub{d7ebc4de04d9d61d05237b5f}` 位于 stash 树的 `193011107810587.txt`；
  恢复仓库可执行 `git stash list` / `git show refs/stash`，证据保留在 ctf2/ 与 ctf2-dump.json。

本地端到端测试：12 个场景 / 1063 项断言全部通过，覆盖松散对象、packed-only、
--history/--write-git（还原后 git status 干净）、index 403 回退、软 404 / 假 HEAD 陷阱、
对象库被封的干净失败、多目标并发与 140 文件逐字节比对；报告见 tests/E2E_REPORT.md。

端到端测试覆盖：松散/打包仓库、软 404、假 HEAD、索引 403 回退、对象 403 失败、
`--resume`、`--write-git`（`git status` 干净）、`--history`、多目标与 `--list`、
字节级还原比对。

## 已知限制

- 只处理标准 Git 对象模型；对服务端做过路径混淆/自定义路由的站点可能无法识别。
- 打包对象读取不校验 `.pack` trailer SHA-1 与 `.idx` CRC（仍会校验对象自身 SHA-1 与长度）。
- `--history` 的提交遍历依赖对数/引用可读；极端历史规模受 `--max-objects` 限制。
- stash 只探测标准 `refs/stash` 路径；若服务端仅剩 `logs/refs/stash` 而删除了 ref 本身，stash 提交无法定位。
- 符号链接在 Windows 上无法创建时，退化为写入目标路径文本文件并给出告警。
