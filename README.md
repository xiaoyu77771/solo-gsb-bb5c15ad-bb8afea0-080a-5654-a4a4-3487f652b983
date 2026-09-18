# IPv4 遮蔽分析 API

基于 **Python + FastAPI** 的 IPv4 CIDR 规则遮蔽（shadowing）分析与等价性比较服务。

按输入顺序处理一组有序的 `allow` / `deny` CIDR 规则，计算每条规则
**未被此前任何规则覆盖**的地址集合，并分为：

| 状态 | 值 | 含义 |
| --- | --- | --- |
| 全生效 | `full` | 规则地址均未被此前规则覆盖 |
| 部分遮蔽 | `partial` | 部分地址此前已被覆盖 |
| 完全遮蔽 | `shadowed` | 全部地址此前已被覆盖，规则不产生任何生效地址 |

每条规则的生效（剩余）地址集合会**无损压缩成数量最少的 CIDR 列表**，
并在 `summary` 中汇总生效的 `allow`、`deny` 地址数。

`POST /compare` 还可比较两组规则（各带未命中时的 `default_action`）在
**整个 IPv4 空间**上的最终判定是否等价，并按 left/right 动作分组给出
判定不同的地址集合及其最少 CIDR 表示。

`POST /explain` 则回答反向问题：给定一段 IPv4 地址空间（`query`），
其中每个地址最终由**哪条规则**（首条匹配）或**默认动作**裁决，
并按规则索引升序给出各归属方的地址集合及其最少 CIDR 表示。

`POST /cidrs/hierarchy` 分析 **1～500 个带唯一 id 的 IPv4 CIDR 条目**的
包含层级：为每个网段选择输入中**前缀最长的严格超网**作为唯一 parent
（没有则作为 root），返回按网络地址、前缀长度与输入顺序稳定排列的树；
每个节点给出 `total_addresses`，以及自身范围扣除全部直接子节点并集后的
`exclusive_address_count` 与无损、数量最少的 `exclusive_cidrs`。

> 遮蔽来源不区分动作：先前的 **allow 与 deny 规则取并集**，共同遮蔽后续规则。

---

## 快速开始（Docker Compose 一条命令）

```bash
docker compose up --build -d
```

服务地址与端口：

- **API 基础地址：** http://localhost:8000
- **分析接口：** `POST http://localhost:8000/analyze`
- **比较接口：** `POST http://localhost:8000/compare`
- **解释接口：** `POST http://localhost:8000/explain`
- **层级接口：** `POST http://localhost:8000/cidrs/hierarchy`
- **交互式文档（Swagger UI）：** http://localhost:8000/docs
- **OpenAPI Schema：** http://localhost:8000/openapi.json
- **健康检查：** http://localhost:8000/health

如需更换宿主机端口（例如改用 18000）：

```bash
HTTP_PORT=18000 docker compose up --build -d
# 随后访问 http://localhost:18000
```

停止服务：

```bash
docker compose down
```

---

## 接口说明

### `POST /analyze`

#### 请求体

```json
{
  "rules": [
    {"action": "allow", "cidr": "10.0.0.0/8"},
    {"action": "deny",  "cidr": "10.1.0.0/16"},
    {"action": "allow", "cidr": "192.168.0.0/16"},
    {"action": "deny",  "cidr": "10.0.0.0/7"}
  ]
}
```

- `rules`：**有序**规则列表，按数组顺序逐条处理；至少 1 条。
- `action`：仅允许 `allow` / `deny`（大小写不敏感，会规范化为小写）。
- `cidr`：严格 IPv4 CIDR（如 `10.0.0.0/8`、`0.0.0.0/0`）；
  纯 IP 地址按 `/32` 处理；**主机位必须为零**（如 `10.0.0.1/8` 非法）；
  **禁止 IPv6**。

#### 响应示例（200）

```json
{
  "rule_count": 4,
  "rules": [
    {
      "index": 0,
      "action": "allow",
      "cidr": "10.0.0.0/8",
      "status": "full",
      "status_label": "全生效",
      "total_addresses": 16777216,
      "covered_addresses": 0,
      "effective_addresses": 16777216,
      "effective_cidrs": ["10.0.0.0/8"]
    },
    {
      "index": 1,
      "action": "deny",
      "cidr": "10.1.0.0/16",
      "status": "shadowed",
      "status_label": "完全遮蔽",
      "total_addresses": 65536,
      "covered_addresses": 65536,
      "effective_addresses": 0,
      "effective_cidrs": []
    },
    {
      "index": 2,
      "action": "allow",
      "cidr": "192.168.0.0/16",
      "status": "full",
      "status_label": "全生效",
      "total_addresses": 65536,
      "covered_addresses": 0,
      "effective_addresses": 65536,
      "effective_cidrs": ["192.168.0.0/16"]
    },
    {
      "index": 3,
      "action": "deny",
      "cidr": "10.0.0.0/7",
      "status": "partial",
      "status_label": "部分遮蔽",
      "total_addresses": 33554432,
      "covered_addresses": 16777216,
      "effective_addresses": 16777216,
      "effective_cidrs": ["11.0.0.0/8"]
    }
  ],
  "summary": {
    "full": 2,
    "partial": 1,
    "shadowed": 1,
    "effective_allow_addresses": 16842752,
    "effective_deny_addresses": 16777216
  }
}
```

`effective_cidrs` 为生效地址集合的最少 CIDR 表示：碎片会先合并
（首尾相邻也合并），再用贪心取最大对齐 2 的幂分块，保证**块数最少且无损**。

#### curl 示例

```bash
curl -s http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"action":"allow","cidr":"0.0.0.0/0"},{"action":"deny","cidr":"8.8.8.8/32"}]}'
```

---

### `POST /compare`

比较两组有序 allow/deny 规则在**整个 IPv4 空间**（`0.0.0.0/0`）上的最终
判定是否等价。两侧各自独立，均沿用 `/analyze` 的 CIDR 校验与
**首条匹配规则生效**的顺序语义；未命中任何规则的地址取该侧的
`default_action`。

#### 请求体

```json
{
  "left": {
    "rules": [
      {"action": "allow", "cidr": "10.0.0.0/8"},
      {"action": "deny",  "cidr": "10.1.0.0/16"}
    ],
    "default_action": "deny"
  },
  "right": {
    "rules": [
      {"action": "deny",  "cidr": "10.1.0.0/16"},
      {"action": "allow", "cidr": "10.0.0.0/8"}
    ],
    "default_action": "deny"
  }
}
```

- `left` / `right`：两侧规则集，结构相同。
  - `rules`：**有序**规则列表（按数组顺序逐条处理），**允许为空** `[]`；
    为空时该侧所有地址都走默认动作。
  - `default_action`：**必填**，未命中任何规则时的最终动作，仅允许
    `allow` / `deny`（大小写不敏感，会规范化为小写）。
- `rules` 内每条规则的 `action` / `cidr` 校验规则与 `/analyze` 完全一致
  （严格 IPv4 CIDR、纯 IP 按 `/32`、主机位必须为零、禁止 IPv6）。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `equivalent` | 两侧在整个 IPv4 空间上的最终判定是否完全一致；为 `true` 时 `differences` 为空 |
| `differences[]` | 判定不同的地址分组，按 `left_action`、`right_action` 组合聚合，最多 2 组 |
| `differences[].left_action` / `.right_action` | 该组地址在左侧 / 右侧的最终动作 |
| `differences[].address_count` | 该组覆盖的地址数（各组之和 ≤ 2³²） |
| `differences[].cidrs` | 该组地址集合**无损压缩后的最少 CIDR 列表** |

分组按 `(left_action, right_action)` 字典序返回：
`(allow, deny)` 在前，`(deny, allow)` 在后。整个比较基于整数区间归并
计算，**不会逐地址枚举 IPv4 空间**。

#### 响应示例（200，不等价）

上例中 `10.1.0.0/16` 左侧先命中 `allow 10.0.0.0/8`，右侧先命中
`deny 10.1.0.0/16`，因此仅这一个 `/16` 的判定不同：

```json
{
  "equivalent": false,
  "differences": [
    {
      "left_action": "allow",
      "right_action": "deny",
      "address_count": 65536,
      "cidrs": ["10.1.0.0/16"]
    }
  ]
}
```

#### 响应示例（200，完全等价）

被此前规则**完全遮蔽**的规则不影响最终判定；`default_action` 大小写不敏感：

请求：

```json
{
  "left": {
    "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
    "default_action": "deny"
  },
  "right": {
    "rules": [
      {"action": "allow", "cidr": "10.0.0.0/8"},
      {"action": "deny",  "cidr": "10.1.0.0/16"}
    ],
    "default_action": "DENY"
  }
}
```

响应：

```json
{
  "equivalent": true,
  "differences": []
}
```

#### 默认动作导致的全空间差异

左侧仅放行 `10.0.0.0/8`、其余默认 `deny`；右侧无规则、默认 `allow`。
除 `10.0.0.0/8` 外的全部地址构成一个 `deny → allow` 组，被压缩为
8 个 CIDR（地址计数 4294967296 − 16777216 = 4278190080）：

请求：

```json
{
  "left": {
    "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
    "default_action": "deny"
  },
  "right": {
    "rules": [],
    "default_action": "allow"
  }
}
```

响应：

```json
{
  "equivalent": false,
  "differences": [
    {
      "left_action": "deny",
      "right_action": "allow",
      "address_count": 4278190080,
      "cidrs": [
        "0.0.0.0/5",
        "8.0.0.0/7",
        "11.0.0.0/8",
        "12.0.0.0/6",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1"
      ]
    }
  ]
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/compare \
  -H 'Content-Type: application/json' \
  -d '{
    "left":  {"rules":[{"action":"allow","cidr":"10.0.0.0/8"}], "default_action":"deny"},
    "right": {"rules": [],                                        "default_action":"allow"}
  }'
```

---

### `POST /explain`

解释一段 IPv4 地址空间（`query`）最终由**哪条规则或默认动作**裁决。
沿用 `/analyze` 的 CIDR 校验与**首条匹配规则生效**的顺序语义，
但只在 `query` 范围内归因：query 中的每个地址归属于首条命中它的规则；
未命中任何规则的部分归于 `default_action`。

#### 请求体

```json
{
  "rules": [
    {"action": "allow", "cidr": "10.0.0.0/16"},
    {"action": "deny",  "cidr": "10.0.1.0/24"},
    {"action": "deny",  "cidr": "10.2.0.0/16"}
  ],
  "default_action": "deny",
  "query": "10.0.0.0/8"
}
```

- `rules`：**有序**规则列表（按数组顺序逐条处理），**允许为空** `[]`；
  为空时整个 query 都走默认动作。每条规则的 `action` / `cidr` 校验规则
  与 `/analyze` 完全一致。
- `default_action`：**必填**，未命中任何规则时的最终动作，仅允许
  `allow` / `deny`（大小写不敏感，会规范化为小写）。
- `query`：**必填**，单个严格 IPv4 CIDR；纯 IP 按 `/32` 处理；
  主机位必须为零；禁止 IPv6。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `query` | 规范化后的 query CIDR（纯 IP 规范化为 `/32`） |
| `total_addresses` | query 覆盖的地址总数 |
| `attribution[]` | 归因列表，**按规则索引升序、默认项最后**；所有项**不重不漏**覆盖整个 query |
| `attribution[].source` | `rule`（命中规则）或 `default`（走默认动作） |
| `attribution[].rule_index` | 命中规则在输入中的序号（从 0 开始）；默认项为 `null` |
| `attribution[].action` | 该项地址的最终动作 |
| `attribution[].address_count` | 该项覆盖的地址数（各项之和 = `total_addresses`） |
| `attribution[].cidrs` | 该项地址集合**无损压缩后的最少 CIDR 列表** |

在 query 范围内被此前规则完全遮蔽、或与 query 不相交的规则不会产生
归因项；若规则已完整覆盖 query，则不出现默认项。

#### 响应示例（200）

上例中 `deny 10.0.1.0/24` 被规则 0 完全遮蔽（不出现）；`10.0.0.0/16`
归规则 0、`10.2.0.0/16` 归规则 2，其余地址走默认动作 `deny`：

```json
{
  "query": "10.0.0.0/8",
  "total_addresses": 16777216,
  "attribution": [
    {
      "source": "rule",
      "rule_index": 0,
      "action": "allow",
      "address_count": 65536,
      "cidrs": ["10.0.0.0/16"]
    },
    {
      "source": "rule",
      "rule_index": 2,
      "action": "deny",
      "address_count": 65536,
      "cidrs": ["10.2.0.0/16"]
    },
    {
      "source": "default",
      "rule_index": null,
      "action": "deny",
      "address_count": 16646144,
      "cidrs": [
        "10.1.0.0/16",
        "10.3.0.0/16",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9"
      ]
    }
  ]
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/explain \
  -H 'Content-Type: application/json' \
  -d '{
    "rules": [{"action":"allow","cidr":"10.0.0.0/16"}],
    "default_action": "deny",
    "query": "10.0.0.0/8"
  }'
```

---

### `POST /cidrs/hierarchy`

分析 **1～500 个带唯一 `id` 的 IPv4 CIDR 条目**的包含层级。

- 对每个网段，选择输入中**前缀最长的严格超网**（strict supernet）作为它的
  **唯一 parent**；不存在严格超网的网段作为 **root**。
- 每个节点给出：
  - `total_addresses`：本网段覆盖的地址总数；
  - `exclusive_address_count`：自身范围扣除**全部直接子节点**并集后的
    独占地址数（孙节点不重复扣除）；
  - `exclusive_cidrs`：该独占地址集合**无损压缩、数量最少**的 CIDR 列表
    （无子节点时就是网段自身）。
- 树（森林）按 **网络地址升序 → 前缀长度升序 → 输入顺序** 稳定排列
  （先根遍历的兄弟顺序）。
- `id` 必须在全请求内唯一（字符串或整数）；**规范化后网络相同**的条目
  （如 `10.0.0.0/8` 与 `10.0.0.0/08`）返回 **422** 并列出冲突 id。
- CIDR 校验与其他接口完全一致：严格 IPv4、纯 IP 按 `/32`、主机位必须为零、
  禁止 IPv6。基于整数区间运算，**不逐地址枚举**。

#### 请求体

```json
{
  "entries": [
    {"id": "net",   "cidr": "10.0.0.0/8"},
    {"id": "sub",   "cidr": "10.1.0.0/16"},
    {"id": "host1", "cidr": "10.1.0.1/32"},
    {"id": "host2", "cidr": "10.1.0.2/32"},
    {"id": "dns",   "cidr": "8.8.8.8"}
  ]
}
```

- `entries`：**必填**，1～500 个条目。
- `id`：非空字符串或整数，全请求内唯一；不接受 `true` / `1.5` 等其他类型，
  不做隐式类型转换。
- `cidr`：严格 IPv4 CIDR；纯 IP 按 `/32` 处理；主机位必须为零；禁止 IPv6。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `node_count` | 节点（条目）总数 |
| `root_count` | 根节点数量 |
| `roots[]` | 根节点组成的森林，按网络地址、前缀长度、输入顺序稳定排序 |
| `roots[].id` / `.cidr` | 节点 id 与规范化后的 CIDR |
| `roots[].parent_id` | 唯一父节点 id（前缀最长的严格超网）；根节点为 `null` |
| `roots[].total_addresses` | 本网段覆盖的地址总数（2^(32−前缀长度)） |
| `roots[].exclusive_address_count` | 自身范围扣除全部直接子节点并集后的地址数 |
| `roots[].exclusive_cidrs` | 独占地址集合**无损压缩后的最少 CIDR 列表** |
| `roots[].children[]` | 直接子节点（递归同构），排序规则与 `roots` 相同 |

#### 响应示例（200）

上例中 `host1` / `host2` 的 parent 是前缀最长的严格超网 `sub`（`/16`），
而非 `net`（`/8`）；`sub` 的独占范围要扣除这两个直接子节点，`net` 只扣除
它的直接子节点 `sub`（孙节点不重复扣除）。`dns`（`8.8.8.8/32`）与
`10.0.0.0/8` 不相交，是另一个 root；根按网络地址升序排列：

```json
{
  "node_count": 5,
  "root_count": 2,
  "roots": [
    {
      "id": "dns",
      "cidr": "8.8.8.8/32",
      "parent_id": null,
      "total_addresses": 1,
      "exclusive_address_count": 1,
      "exclusive_cidrs": ["8.8.8.8/32"],
      "children": []
    },
    {
      "id": "net",
      "cidr": "10.0.0.0/8",
      "parent_id": null,
      "total_addresses": 16777216,
      "exclusive_address_count": 16711680,
      "exclusive_cidrs": [
        "10.0.0.0/16",
        "10.2.0.0/15",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9"
      ],
      "children": [
        {
          "id": "sub",
          "cidr": "10.1.0.0/16",
          "parent_id": "net",
          "total_addresses": 65536,
          "exclusive_address_count": 65534,
          "exclusive_cidrs": [
            "10.1.0.0/32",
            "10.1.0.3/32",
            "10.1.0.4/30",
            "10.1.0.8/29",
            "10.1.0.16/28",
            "10.1.0.32/27",
            "10.1.0.64/26",
            "10.1.0.128/25",
            "10.1.1.0/24",
            "10.1.2.0/23",
            "10.1.4.0/22",
            "10.1.8.0/21",
            "10.1.16.0/20",
            "10.1.32.0/19",
            "10.1.64.0/18",
            "10.1.128.0/17"
          ],
          "children": [
            {
              "id": "host1",
              "cidr": "10.1.0.1/32",
              "parent_id": "sub",
              "total_addresses": 1,
              "exclusive_address_count": 1,
              "exclusive_cidrs": ["10.1.0.1/32"],
              "children": []
            },
            {
              "id": "host2",
              "cidr": "10.1.0.2/32",
              "parent_id": "sub",
              "total_addresses": 1,
              "exclusive_address_count": 1,
              "exclusive_cidrs": ["10.1.0.2/32"],
              "children": []
            }
          ]
        }
      ]
    }
  ]
}
```

#### 错误示例（422，规范化后网络重复）

请求中 `b` 与 `a` 规范化后指向同一网络，返回 422 并在
`duplicate_networks[].entries` 中列出冲突条目（含冲突 id）：

```json
{
  "detail": {
    "error": "duplicate_entries",
    "duplicate_ids": [],
    "duplicate_networks": [
      {
        "cidr": "10.0.0.0/8",
        "entries": [
          {"index": 0, "id": "a", "cidr": "10.0.0.0/8"},
          {"index": 1, "id": "b", "cidr": "10.0.0.0/8"}
        ]
      }
    ]
  }
}
```

`id` 重复时，冲突位置列在 `duplicate_ids`（每项含 `id` 与全部出现位置
`indexes`）；两类问题可能同时出现。

#### curl 示例

```bash
curl -s http://localhost:8000/cidrs/hierarchy \
  -H 'Content-Type: application/json' \
  -d '{"entries":[{"id":"net","cidr":"10.0.0.0/8"},{"id":"sub","cidr":"10.1.0.0/16"},{"id":"host","cidr":"10.1.1.1"}]}'
```

### 错误响应（422 Unprocessable Entity）

以下输入均返回 HTTP `422`，错误明细位于 `detail`：

- 空规则集（仅 `/analyze`）：`{"rules": []}` 或缺少 `rules`
- `/compare` 缺少 `left` / `right`，或任一侧缺少 `default_action`
- `/explain` 缺少 `query` 或 `default_action`
- `/cidrs/hierarchy` 缺少 `entries`、条目数不在 1～500、`id` 缺失/为空/
  类型非法（如 `true`、`1.5`）、**`id` 重复**或**规范化后网段重复**
  （后两者在 `detail.duplicate_ids` / `detail.duplicate_networks` 中列出
  冲突 id 与位置）
- 非法 CIDR：格式错误、前缀越界（`/33`）、主机位非零（`10.0.0.1/8`）等
- IPv6 地址或网段：`2001:db8::/32`、`::1` 等
- 非法 / 缺失 `action` 或 `default_action`、字段类型错误、JSON 格式错误

---

## 本地开发（不使用 Docker）

需要 Python 3.11+。

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

运行测试：

```bash
pytest -q
```

测试覆盖：解析校验（含 IPv6 拒绝）、区间差集与合并、最少 CIDR 压缩、
三种遮蔽分类、跨动作遮蔽、顺序敏感性，`/compare` 的等价判定、顺序/默认
动作差异、双向分组与全空间压缩，`/explain` 的归因归属、默认项位置、
不重不漏覆盖，`/cidrs/hierarchy` 的最长前缀超网择父、森林稳定排序、
独占集合（仅扣直接子节点）、重复 id / 重复网段 422 与 1～500 数量边界，
以及用标准库 `ipaddress.collapse_addresses` 作为 oracle 的随机属性测试
（无损 + 最少块，并与逐地址暴力判定对比）。

---

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── analyzer.py    # 核心：CIDR 解析、区间差集、最少 CIDR 压缩、规则分析、等价比较、裁决归因与包含层级
│   └── main.py        # FastAPI 应用、请求/响应模型与 /analyze、/compare、/explain、/cidrs/hierarchy 接口
├── tests/
│   ├── test_analyzer.py
│   └── test_api.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## 设计要点

- **遮蔽语义**：处理第 *i* 条规则时，遮蔽集合 = 前 *i-1* 条规则
  （allow ∪ deny）覆盖地址的并集；规则区间减去遮蔽集合即生效集合。
- **无损压缩**：剩余碎片先合并相邻区间，再以“当前地址能对齐的最大
  2 的幂块、且不越过区间末端”贪心切块，得到最少数量的 CIDR。
- **等价比较**：先为每侧构造覆盖整个 IPv4 空间的有序判定分区
  （规则生效碎片 + 未命中地址的 default_action），再以双指针归并两个
  分区，交叠处动作不同即记入对应 `(left_action, right_action)` 分组；
  分组碎片同样走“合并 + 贪心切块”。时间复杂度仅取决于区间数量，
  **不逐地址枚举**，可安全处理 `0.0.0.0/0` 全空间。
- **裁决归因**：`/explain` 复用同一套区间运算，把每条规则的生效碎片
  裁剪到 query 范围并记到该规则名下，query 内未被任何规则覆盖的剩余
  部分记为默认项；各归属集合分别做“合并 + 贪心切块”，最终按规则索引
  升序、默认项最后输出，不重不漏覆盖整个 query。
- **包含层级**：`/cidrs/hierarchy` 先按严格 IPv4 校验解析全部条目并
  检查 id 与规范化网段的唯一性；为每个网段在全部条目中选择前缀最长的
  严格超网作为唯一 parent（无同网段重复时该选择唯一），形成森林。
  节点独占集合 = 自身区间减去其**直接子节点**区间并集（孙节点已包含在
  子节点内，不重复扣除），再走“合并 + 贪心切块”得到数量最少的
  `exclusive_cidrs`；兄弟节点按 `(网络地址, 前缀长度, 输入序号)` 稳定
  排序。全程为区间运算，不逐地址枚举。
- **整数运算**：全部基于 32 位无符号整数区间处理，避免字符串/对象开销，
  可正确支持 `0.0.0.0/0` 全空间等边界场景。
