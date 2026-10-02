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
- `app/api`、`app/services` 和 `app/repositories` 提供身份、权限、审计、后台作业及维护能力。

## 一致性约定

SQLite 连接启用外键、WAL、忙等待和即时写事务。案件档案、库位、容器摆放、检验任务和领用申请采用版本号防止旧请求覆盖新状态；入库、移库、取样和传感读数使用业务键去重。专业检验保留采用的规程版本和每个检查点的观察记录，完成后可依据鉴定专业及风险策略生成下一次复核日期。会话令牌只保存摘要，审计记录不保存明文密码或令牌。

## 审计归档快照

`app/archives` 在 `audit_events` 之上提供可校验的季度归档，全部操作只读线上审计事件，不回写业务状态。

- **冻结范围**：`POST /api/audit/archives` 由具备 `audit.archive` 权限的管理员选定截止事件（`end_event_id`）与脱敏策略（令牌、联系方式、受限案件），并固化分块大小与封存时刻。快照指纹只依赖这些固化输入，因此同一输入重复执行得到相同标识；策略、截止点或封存时刻变化必然产生新指纹，只能新建版本，旧归档永不被覆盖。
- **分块连续摘要**：`POST /api/audit/archives/{id}/generate` 按稳定游标（按事件 ID 升序、固定分块大小）生成清单。每条规范化事件有独立摘要，块内用"前一条目摘要 + 当前条目"做连续摘要，分块摘要再与前一分块串联，根摘要登记在快照上并附封存密钥的 HMAC 签名（防止有库写权限者整体重写）。任何删除、插入、重排或字段变化都会在校验时暴露。每个分块独立提交，中断后已确认分块即恢复点，可安全重复续跑。
- **脱敏与可复核原值**：联系方式按权限掩码展示、令牌与受限案件载荷替换为带 HMAC 承诺的标记（封存密钥保存在 `app_secrets`，只用于承诺，不参与公开指纹）。无 `audit.archive` 权限者只能看到脱敏视图与承诺；有权者可通过 `reveal=true` 或 `profile=canonical` 导出原值并独立验证每个承诺。
- **审计与运维入口**：审计员（`audit.verify`）可通过 `GET /api/audit/archives/{id}/verify`、`/chunks`、`/events` 查看进度、覆盖区间与失败原因；运维命令 `python -m app.cli archive freeze|generate|list|show|verify|export|verify-file|secret` 提供同等能力，`verify-file` 可对导出包做脱离数据库的离线校验（篡改时退出码为 2）。离线校验在不提供封存密钥时证明包内部链自洽；提供密钥（`--secret-env` 或 `--with-database-secret`）后可进一步验证根签名与全部脱敏承诺，识别整体伪造。
- **追溯**：`GET /api/audit/archives/{id}/events/{event_id}/trace` 从快照条目回溯线上原审计事件并比对摘要。

导出包分三个剖面：`manifest`（仅摘要链）、`redacted`（含脱敏视图，默认）、`canonical`（含规范化原值，需 `audit.archive` 权限）。

