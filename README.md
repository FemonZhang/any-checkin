# AnyRouter 自动签到

使用 GitHub Actions 每日自动签到 [AnyRouter](https://anyrouter.top)，支持多账号。

> 本仓库为公开仓库，使用标准 Runner，**完全免费**，无分钟限制。

---

## 使用方法（Fork 后配置）

### 1. Fork 本仓库

点击右上角 **Fork**，把仓库复制到自己的账号下。

### 2. 配置 Secret（必须）

1. 打开你 Fork 后的仓库
2. 进入 **Settings** → **Secrets and variables** → **Actions**
3. 点击 **New repository secret**
4. 名称填写：

```text
ANY_ACCOUNTS_JSON
```

5. 值填写以下 JSON（替换成自己的真实信息）：

```json
{
  "base_url": "https://anyrouter.top",
  "proxy": "direct",
  "schedule_time": "08:05",
  "jitter_seconds": 180,
  "request_timeout_seconds": 30,
  "retries": 3,
  "account_delay_min_seconds": 2,
  "account_delay_max_seconds": 6,
  "log_file": "logs/anyrouter-checkin.log",
  "accounts": [
    {
      "name": "账号1",
      "enabled": true,
      "cookie": "session=这里填你的完整cookie",
      "user_id": 12345
    },
    {
      "name": "账号2",
      "enabled": true,
      "cookie": "session=另一个账号的cookie",
      "user_id": 67890
    }
  ]
}
```

> **如何获取 cookie 和 user_id：**
> 1. 浏览器登录 [anyrouter.top](https://anyrouter.top)
> 2. 按 `F12` → **Application** → **Cookies** → 复制 `session` 等完整内容
> 3. `user_id` 可在请求头参数**new-api-user**获取

### 3. 启用并测试 Action

1. 打开仓库的 **Actions** 页面
2. 如果提示启用工作流，点击 **I understand my workflows, go ahead and enable them**
3. 选择左侧 **AnyRouter Daily Check-in**
4. 点击 **Run workflow** → **Run workflow** 进行手动测试
5. 查看运行日志，确认出现 `signed` 或 `already_signed` 即表示成功

---

## 运行时间

默认每天 **北京时间 08:05** 左右自动执行（对应 UTC `0 5 * * *`）。

如需修改时间，编辑 `.github/workflows/checkin.yml` 中的 cron 表达式即可。

---

## 注意事项

- Cookie 有有效期，失效后重新获取并更新 Secret 即可
- Secret 内容只有你自己能看到，其他人无法查看
- 请勿把真实 cookie 提交到仓库代码中
- 支持多账号，在 JSON 的 `accounts` 数组中继续添加即可

---

## 免责声明

本项目仅供学习与个人使用，请遵守网站相关规定。使用本脚本所产生的一切后果由使用者自行承担。
