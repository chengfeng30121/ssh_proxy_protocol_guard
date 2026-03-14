# SSH Proxy Protocol Guard (SPPG)
SSH Proxy Protocol Guard (下文简称SPPG) 是一个针对解析 Proxy Protocol 的 SSH 代理，基于 Python 编写。

## 原理
SPPG 通过解析传入连接的 Proxy Protocol 头来获取源 IP 地址，然后通过 socket 将剩下的数据传给 SSHD 服务器，因为是针对 Termux 所写，因此默认 SSHD 日志路径为 `/data/data/com.termux/files/usr/var/log/auth.log`，默认 SSHD 端口为 8022，服务端口为 18022。
由于 Termux 不支持 PAM 认证，因此本项目并未绑定任何和 PAM 相关的功能。至于认证的实现，也并没有解析数据包，而是通过了一种巧妙的方式。当客户端建立连接时，SPPG 会先解析并记录客户端的 IP 地址并和连接进行对应，随后 SPPG 会去除 Proxy Protocol 数据，然后和 SSHD 服务器建立连接，并记录 SPPG 和 SSHD 连接的端口号。当日志检测器检测到 SSHD 错误日志并且能和 SPPG 的连接端口号对应时，就会将连接到 SPPG 的客户端的真实 IP 地址记录。当错误超过 5 次(默认)时，SPPG 会封禁该 IP 地址 1 时(默认)，并记录封禁信息。

## 运行
本项目需要cfpackages实现logger格式化，安装命令 `pip install -U cfpackages`，开发环境 Python 3.13，建议运行在 Python 3.10+ 环境，使用前请将 `constants.py` 中的 `DEFAULT_SSHD_LOG_PATH` 修改为 SSHD 日志路径或运行后在 `SSH_Proxy/config.json` 中修改。

## 声明
本项目仍在开发阶段，逻辑上可能有所欠缺，欢迎提交 PR 和 Issue。
