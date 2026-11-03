package i18n

// zh maps English source strings to their Chinese translations. Keys are the
// exact English format strings used by the program; a missing key simply keeps
// the English text.
var zh = map[string]string{
	// banner
	"fast .git leak scanner & repository dumper":          "快速 .git 泄露扫描与仓库还原工具",
	"use only against systems you are authorised to test": "仅可用于已获授权的系统测试",

	// dump.go
	"  target: %s":                        "  目标: %s",
	"  output: %s":                        "  输出: %s",
	"downloaded pack %s (%d objects, %s)": "已下载 pack %s（%d 个对象，%s）",
	"recovered %d file(s) from refs/stash (%s) into .gitleak-stash/": "已从 refs/stash 恢复 %d 个文件（%s）到 .gitleak-stash/",
	"restored %d files (%s) from %s":                                 "已从 %[3]s 恢复 %[1]d 个文件（%[2]s）",
	"recovered history: %d commits, %d objects (%s)":                 "已恢复历史：%d 个提交、%d 个对象（%s）",

	// history.go
	"  downloading pack index %s":        "  正在下载 pack 索引 %s",
	"  downloading pack %s (%d objects)": "  正在下载 pack %s（%d 个对象）",
	"history: %d objects":                "历史：%d 个对象",

	// scan.go / secrets.go
	"scan %d/%d  found=%d  req=%d  %.0f req/s  err=%d": "扫描 %d/%d  发现=%d  请求=%d  %.0f 请求/秒  错误=%d",
	"possible secret in %s: %s":                        "在 %s 中发现疑似密钥：%s",

	// cli.go
	"auto mode: detect + full dump (--history --all-branches --write-git)": "自动模式：探测并完整还原（--history --all-branches --write-git）",
	"  report: %s": "  报告: %s",
	"requests=%d retries=%d errors=%d bytes=%s 2xx=%d 4xx=%d 5xx=%d": "请求=%d 重试=%d 错误=%d 字节=%s 2xx=%d 4xx=%d 5xx=%d",
	"targets=%d vulnerable=%d restored=%d files=%s":                  "目标=%d 存在泄露=%d 已恢复=%d 文件=%s",

	// compact summary line
	"%s  (not vulnerable)":                    "%s  （未发现 .git 泄露）",
	"%s  (error: %s)":                         "%s  （错误：%s）",
	"target does not expose a .git directory": "目标未暴露 .git 目录",

	// command line errors
	"gitleak: unknown subcommand %q\n\n%s":                   "gitleak: 未知子命令 %q\n\n%s",
	"gitleak: %v\n\n%s":                                      "gitleak: 参数错误：%v\n\n%s",
	"gitleak: cannot read target list: %v\n":                 "gitleak: 无法读取目标列表：%v\n",
	"gitleak: skipping %q: %v\n":                             "gitleak: 跳过 %q：%v\n",
	"gitleak: cannot write report: %v\n":                     "gitleak: 无法写入报告：%v\n",
	"gitleak: dump expects exactly one target, got %d\n\n%s": "gitleak: dump 需要且仅需要一个目标，实际收到 %d 个\n\n%s",
	"gitleak: --no-extract cannot be combined with --auto":   "gitleak: --no-extract 不能与 --auto 同时使用",
	"--timeout must be positive":                             "--timeout 必须为正数",
	"--max-body must be positive":                            "--max-body 必须为正数",
	"--out must not be empty":                                "--out 不能为空",
	"invalid header %q (want K:V)":                           "无效的请求头 %q（格式应为 K:V）",

	// secret finding kinds (console warning only; JSON keeps the English kind)
	"AWS access key id":    "AWS 访问密钥 ID",
	"Private key block":    "私钥块",
	"GitHub token":         "GitHub 令牌",
	"Slack token":          "Slack 令牌",
	"Google API key":       "Google API 密钥",
	"Stripe secret key":    "Stripe 私钥",
	"JSON web token":       "JSON Web 令牌",
	"Hardcoded credential": "硬编码凭据",
}
