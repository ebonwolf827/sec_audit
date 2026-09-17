# 社区 YARA 规则

本目录存放从开源项目引入的 YARA 规则。

## 引入来源

| 项目 | 地址 | 许可 | 说明 |
|---|---|---|---|
| yara-detection-rules | https://github.com/leonardosmoutinho/yara-detection-rules | MIT | Webshell、勒索软件、C2 规则 |
| signature-base | https://github.com/Neo23x0/signature-base | DRL 1.1 | 恶意软件签名库 |
| YARA-Rules/rules | https://github.com/Yara-Rules/rules | 混合 | 社区规则集 |

## 更新方式

社区规则通过 `check_yara.sh` 的 `update_community_rules()` 自动更新。
也可以手动更新：

```bash
cd /usr/local/bin/sec_audit/rules/community/yara-detection-rules
git pull

cd /usr/local/bin/sec_audit/rules/community/signature-base
git pull

# 重新编译
/usr/local/bin/sec_audit/sec_audit.sh --no-install
