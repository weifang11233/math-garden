# 部署与脱敏还原说明

本仓库代码已脱敏，**不能直接部署**。首次部署或重置环境时，需按下方占位符表把真实值回填到对应文件。

## 一、占位符清单（必须替换）

用文本编辑器全局替换以下占位符：

| 占位符 | 含义 | 出现文件 |
|---|---|---|
| `NAS_HOST_REPLACE_ME` | NAS 内网 IP（如 `192.168.31.88`） | `nginx.conf`、`api-server/server.js` |
| `ADMIN_PHONE_REPLACE_ME` | 管理员手机号 | `api-server/server.js`、`site/index.html` |
| `ADMIN_SALT_REPLACE_ME` | 管理员密码 salt（16 位 hex） | `api-server/server.js`、`site/index.html` |
| `ADMIN_HASH_REPLACE_ME` | 管理员密码 hash（64 位 hex） | `api-server/server.js`、`site/index.html` |
| `sk-REPLACE_WITH_YOUR_AI_GATEWAY_KEY` | AI 判分网关 Key | `nginx.conf` |
| `REPLACE_WITH_YOUR_FREELLMAPI_KEY` | freellmapi 兼容 Key（如使用旧网关） | `nginx.conf`（历史配置） |

> 管理员 hash 算法：`sha256(salt + '::' + 明文密码)`，与前端 `hashPass()` 一致。
> 前端与后端两处的 `ADMIN_PHONE/SALT/HASH` 必须完全一致。

## 二、部署步骤（飞牛 NAS）

```bash
cd /vol3/1000/docker/shuxueleyuan

# 1. 备份线上旧版（务必）
cp api-server/server.js api-server/server.js.bak-$(date +%Y%m%d-%H%M)
cp site/index.html site/index.html.bak-$(date +%Y%m%d-%H%M)
cp nginx.conf nginx.conf.bak-$(date +%Y%m%d-%H%M)

# 2. 覆盖程序文件（数据目录 api-server/data 绝不能动）
cp <本仓库>/api-server/server.js api-server/server.js
cp <本仓库>/site/index.html      site/index.html
cp <本仓库>/site/books/*.js      site/books/
cp <本仓库>/nginx.conf           nginx.conf

# 3. 语法检查
docker exec shuxue-api node --check /app/server.js

# 4. 重启服务
docker restart shuxue-api
docker restart shuxueleyuan

# 5. 验证报告镜像同步状态
#    管理员登录后调用 GET /api/admin/report/mirror，确认 verify.ok === true
```

## 三、数据安全

- `api-server/data/`（用户表、会话、学习存档、报告镜像）**从不入库**，仅存在 NAS 本地
- 每次升级前先做数据基线快照，升级只覆盖程序文件
- 报告镜像由服务启动时自动全量对账生成，无需手工干预
