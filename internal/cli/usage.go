package cli

import "gitleak/internal/i18n"

const usageEN = `gitleak - fast .git exposure scanner and repository dumper

Usage:
  gitleak --auto [flags] <url>   one-shot full dump (implies --history --all-branches --write-git)
  gitleak scan [flags] <url...>
  gitleak dump [flags] <url>
  gitleak auto [flags] <url...>  scan, then dump the vulnerable targets
  gitleak version

Flags:
  -l, --list FILE      read targets from FILE (- for stdin)
  -o, --out DIR        output directory (default gitleak-out)
      --json FILE      write the JSON report to FILE
      --auto           top-level auto mode: detect + full history dump, JSON auto-written
  -c, --concurrency N  global concurrent requests (default 64)
      --per-host N     concurrent requests per host (default 8)
      --rate N         request rate limit per second (0 = unlimited)
  -t, --timeout D      per request timeout (default 10s)
      --retries N      retries per request (default 3)
  -A, --user-agent UA  User-Agent header
  -H, --header K:V     extra request header (repeatable)
      --proxy URL      HTTP or SOCKS5 proxy URL
  -k, --insecure       skip TLS certificate verification
      --max-body MB    maximum response body size in MB (default 64)
      --threads N      worker goroutines (default 32)
      --history        download the full commit history
      --all-branches   follow every ref while downloading history
      --write-git      materialise a usable .git directory (implies --history)
      --resume         reuse previously cached objects
      --scan-secrets   scan restored files for credentials
      --extra          probe extra leak paths (.svn, .hg, .env, ...)
      --no-extract     detect only, download nothing
      --max-pack MB    maximum packfile size in MB (default 1024)
      --max-objects N  maximum history objects (default 200000)
      --lang en|zh     output language (env GITLEAK_LANG)
      --debug          verbose debug output
      --quiet          suppress banners and progress
      --no-color       disable ANSI colours

Auto mode: gitleak --auto <url> writes <out>/<slug>.json next to the restored repository.
Exit codes: 0 success (found / restored), 2 nothing found, 3 operational failure, 1 usage.
Use this tool only against systems you are authorised to test.
`

const usageZH = `gitleak - 快速 .git 泄露扫描与仓库还原工具

用法：
  gitleak --auto [选项] <url>   一键完整还原（隐含 --history --all-branches --write-git）
  gitleak scan [选项] <url...>
  gitleak dump [选项] <url>
  gitleak auto [选项] <url...>  先扫描，再还原存在泄露的目标
  gitleak version

选项：
  -l, --list FILE      从文件读取目标（- 表示标准输入）
  -o, --out DIR        输出目录（默认 gitleak-out）
      --json FILE      将 JSON 报告写入文件
      --auto           顶层自动模式：探测并完整还原，自动写 JSON 报告
  -c, --concurrency N  全局并发请求数（默认 64）
      --per-host N     每主机并发请求数（默认 8）
      --rate N         每秒请求速率限制（0 表示不限制）
  -t, --timeout D      单请求超时（默认 10s）
      --retries N      单请求重试次数（默认 3）
  -A, --user-agent UA  User-Agent 请求头
  -H, --header K:V     额外请求头（可重复）
      --proxy URL      HTTP 或 SOCKS5 代理地址
  -k, --insecure       跳过 TLS 证书校验
      --max-body MB    响应体最大大小，单位 MB（默认 64）
      --threads N      工作协程数（默认 32）
      --history        下载完整提交历史
      --all-branches   下载历史时跟踪全部引用
      --write-git      生成可用的 .git 目录（隐含 --history）
      --resume         复用之前缓存的对象
      --scan-secrets   扫描已恢复文件中的凭据
      --extra          额外探测其他泄露路径（.svn、.hg、.env 等）
      --no-extract     仅探测，不下载
      --max-pack MB    packfile 最大大小，单位 MB（默认 1024）
      --max-objects N  历史对象数量上限（默认 200000）
      --lang en|zh     输出语言（环境变量 GITLEAK_LANG）
      --debug          输出调试信息
      --quiet          不显示横幅和进度
      --no-color       禁用 ANSI 颜色

自动模式：gitleak --auto <url> 会在还原目录旁写入 <out>/<slug>.json。
退出码：0 成功（发现/恢复），2 未发现，3 运行失败，1 用法错误。
请仅在获得授权的系统上使用本工具。
`

// usageText is selected from the active language at startup.
var usageText = usageEN

func usageFor(l i18n.Lang) string {
	if l == i18n.ZH {
		return usageZH
	}
	return usageEN
}
