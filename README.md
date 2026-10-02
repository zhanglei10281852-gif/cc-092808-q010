# 司法鉴定检材流转与复核服务

本项目是面向司法鉴定机构的 Python 后端服务，用于登记委托或移送案件、接收带封识的检材、记录保管位置与流转、执行专业检验、安排复核并处理环境和质量告警。案件、检材、检验记录和领用审批都保存在本地 SQLite 中，关键写入带版本或幂等键，适合在单个 Linux 应用容器内运行。

## 运行环境

- Python 3.11
- FastAPI 与 Uvicorn
- SQLite 3，由 Python 标准库提供

## 安装

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

默认数据库位于 `data/forensics.db`，也可以通过 `FORENSICS_DATABASE_PATH` 指向其他 `.db`、`.sqlite` 或 `.sqlite3` 文件。

## 初始化与启动

```bash
python -m app.cli init-db
python -m app.cli check-db
uvicorn app.main:app --host 0.0.0.0 --port 8432
```

健康检查为 `GET /api/system/health`。首次使用可调用 `POST /api/auth/bootstrap` 创建管理员，再通过 `POST /api/auth/login` 取得 Bearer 会话令牌。鉴定业务接口统一位于 `/api/forensics`。

## 测试与构建检查

```bash
python -m pytest
python -m compileall -q app tests
```

下面两条命令分别检查 HTTP 入口和完整的入库演示链路：

```bash
python -m app.cli smoke
python -m app.cli demo
```

## 业务边界

- `app/forensics/cases.py` 管理委托机构、案件档案、委托资料与受理状态。
- `app/forensics/custody.py` 管理检材、库位容量、容器摆放、流转、领用和冻结。
- `app/forensics/examinations.py` 管理检验规程、取样、观察记录、检验结果与复核日程。
- `app/forensics/quality.py` 管理温湿度读数、偏离告警和检材领用审批。
- `app/archives` 在审计事件之上建立可校验的归档快照：冻结范围、分块连续摘要、脱敏信封与独立校验。
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 审计归档快照

普通导出只是一批可修改的记录，无法证明截止时刻库中包含哪些事件。归档快照把“截止事件 + 脱敏策略 + 分块大小”冻结为不可变范围，再按主键稳定游标分块生成清单，为每条规范化事件和每个分块建立 SHA-256 连续摘要，最终给出清单根摘要 `manifest_hash`。任何删除、插入、重排或字段变化都会在校验端暴露。

- 冻结：`POST /api/audit-archives/freeze`（权限 `audit.archive.freeze`），请求体指定 `cutoff_event_id`、`policy_code`（`none`/`standard`/`strict`）、`scope_start_id`、`chunk_size`。冻结时固化该区间内的事件标识锚点。
- 生成：`POST /api/audit-archives/{id}/generate`（`audit.archive.generate`），逐块独立提交；中断后重跑只补未确认分块，已确认分块不重算，同一快照重复执行得到相同根摘要。
- 查看：`GET /api/audit-archives`、`/{id}`、`/{id}/progress`（含状态、百分比、失败原因、逐块覆盖区间）、`/{id}/chunks/{seq}`（`audit.archive.read`；带 `reveal=true` 需 `audit.archive.review`）。
- 校验：`POST /api/audit-archives/{id}/verify`（`audit.archive.verify`，`deep=true` 回溯线上原值，需复核权限）；`GET /{id}/events/{event_id}/provenance` 从快照追溯到线上原审计事件而不改动业务状态；`POST /{id}/events/{event_id}/verify-value`（需复核权限）由有权复核者提交原值与路径，校验其与脱敏信封一致。
- 导出与离线校验：`GET /{id}/bundle` 导出含全部事件、分块摘要和锚点的归档包；运维命令 `archive-export` 落盘、`archive-verify-bundle [--manifest-hash …]` 不连数据库即可独立校验，传入可信留档根摘要还能识破整体替换重算。

脱敏策略：`standard` 对令牌、联系方式（电话、证件号、邮箱、地址）及文本中内嵌的联系方式按查看者权限掩码；`strict` 在此基础上对受限案件（`forensic_cases.status='restricted'`）事件整段屏蔽。掩码值替换为“信封”，信封不含原值，只保存掩码和与快照密钥绑定的 HMAC 原值证据——无密钥的读取方无法离线枚举原值，有权复核者可独立验证原值。

同一范围使用完全相同的策略、参数和分块大小重复冻结是幂等的（同一标识）；策略或参数变化会在同一序列下创建新版本（`UNIQUE(series_key,version)`），旧归档永不被覆盖。

运维命令：

```bash
python -m app.cli archive-freeze <cutoff_event_id> [--start-event-id N] [--policy standard|strict|none] [--chunk-size 200]
python -m app.cli archive-generate <snapshot_id>
python -m app.cli archive-progress <snapshot_id>
python -m app.cli archive-verify <snapshot_id> [--deep]
python -m app.cli archive-export <snapshot_id> <path>
python -m app.cli archive-verify-bundle <path> [--manifest-hash <hash>]
```

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。会话令牌只保存摘要，审计记录不保存明文密码或令牌。
