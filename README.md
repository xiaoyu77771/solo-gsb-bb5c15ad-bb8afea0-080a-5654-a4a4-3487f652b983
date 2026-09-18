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

`POST /cidrs/hierarchy` 则对 1～500 个带唯一 `id` 的 CIDR 条目做
**包含层级分析**：为每个网段选择输入中前缀最长的严格超网作为唯一
parent，返回按网络地址、前缀长度与输入顺序稳定排列的层级树，并给出
每个网段扣除全部直接子节点并集后的独占地址数及其最少 CIDR 表示。

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

对 **1～500** 个带唯一 `id` 的 IPv4 CIDR 条目做包含层级分析：

- 对每个网段，在输入中找一个**前缀最长的严格超网**作为它的**唯一 parent**；
  不存在任何严格超网时作为 **root**。同前缀长度的两个不同网络不可能同时
  严格包含第三个网络，因此最长超网天然唯一。
- 返回一棵（或多棵）层级树；根节点之间、同一父节点的子节点之间均按
  **网络地址升序 → 前缀长度升序 → 输入顺序**稳定排列。
- 每个节点给出 `total_addresses`（本网段地址总数），以及其范围扣除
  **全部直接子节点**地址并集后的 `exclusive_address_count` 与
  `exclusive_cidrs`（与 `/analyze` 相同的“合并 + 贪心切块”，
  **无损且 CIDR 数量最少**）。直接子节点两两不相交，并集即区间直接相减，
  全程不逐地址枚举。

#### 请求体

```json
{
  "entries": [
    {"id": "internet", "cidr": "0.0.0.0/0"},
    {"id": "ten",       "cidr": "10.0.0.0/8"},
    {"id": "ten16",     "cidr": "10.0.0.0/16"},
    {"id": "subnet",    "cidr": "10.0.1.0/24"},
    {"id": "lan",       "cidr": "192.168.0.0/16"}
  ]
}
```

- `entries`：**1～500** 个条目，每个条目包含：
  - `id`：**必填**的非空字符串，且所有条目**唯一**（纯空白非法）。
  - `cidr`：严格 IPv4 CIDR（如 `10.0.0.0/8`、`0.0.0.0/0`）；纯 IP 按
    `/32` 处理；主机位必须为零；禁止 IPv6。**规范化后网络相同**的多个条目
    （如 `8.8.8.8` 与 `8.8.8.8/32`）视为冲突。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `entry_count` | 输入条目总数 |
| `root_count` | 根节点（无严格超网）数量 |
| `roots[]` | 根节点列表，按网络地址、前缀长度、输入顺序排列 |
| `roots[].id` / `.cidr` | 条目 id 与规范化后的 CIDR |
| `roots[].total_addresses` | 该网段覆盖的地址总数（2³²⁻ᵖʳᵉᶠⁱˣ） |
| `roots[].exclusive_address_count` | 本网段扣除全部直接子节点并集后独占的地址数 |
| `roots[].exclusive_cidrs` | 独占地址集合**无损压缩后的最少 CIDR 列表**（无独占地址时为 `[]`） |
| `roots[].children[]` | 直接子节点（以本节点为唯一最长严格超网的网段），结构与根节点递归相同 |

每个节点都满足：`total_addresses` = 自身 `exclusive_address_count` +
全部直接子节点 `total_addresses` 之和。

#### 响应示例（200）

上例中 `0.0.0.0/0` 是唯一根；`10.0.1.0/24` 的直接 parent 是
`10.0.0.0/16`（最长严格超网），而非 `10.0.0.0/8`；`192.168.0.0/16`
与 `10.0.0.0/8` 同为 `/0` 的直接子节点，按网络地址排列：

```json
{
  "entry_count": 5,
  "root_count": 1,
  "roots": [
    {
      "id": "internet",
      "cidr": "0.0.0.0/0",
      "total_addresses": 4294967296,
      "exclusive_address_count": 4278124544,
      "exclusive_cidrs": [
        "0.0.0.0/5",
        "8.0.0.0/7",
        "11.0.0.0/8",
        "12.0.0.0/6",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/2",
        "192.0.0.0/9",
        "192.128.0.0/11",
        "192.160.0.0/13",
        "192.169.0.0/16",
        "192.170.0.0/15",
        "192.172.0.0/14",
        "192.176.0.0/12",
        "192.192.0.0/10",
        "193.0.0.0/8",
        "194.0.0.0/7",
        "196.0.0.0/6",
        "200.0.0.0/5",
        "208.0.0.0/4",
        "224.0.0.0/3"
      ],
      "children": [
        {
          "id": "ten",
          "cidr": "10.0.0.0/8",
          "total_addresses": 16777216,
          "exclusive_address_count": 16711680,
          "exclusive_cidrs": [
            "10.1.0.0/16",
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
              "id": "ten16",
              "cidr": "10.0.0.0/16",
              "total_addresses": 65536,
              "exclusive_address_count": 65280,
              "exclusive_cidrs": [
                "10.0.0.0/24",
                "10.0.2.0/23",
                "10.0.4.0/22",
                "10.0.8.0/21",
                "10.0.16.0/20",
                "10.0.32.0/19",
                "10.0.64.0/18",
                "10.0.128.0/17"
              ],
              "children": [
                {
                  "id": "subnet",
                  "cidr": "10.0.1.0/24",
                  "total_addresses": 256,
                  "exclusive_address_count": 256,
                  "exclusive_cidrs": ["10.0.1.0/24"],
                  "children": []
                }
              ]
            }
          ]
        },
        {
          "id": "lan",
          "cidr": "192.168.0.0/16",
          "total_addresses": 65536,
          "exclusive_address_count": 65536,
          "exclusive_cidrs": ["192.168.0.0/16"],
          "children": []
        }
      ]
    }
  ]
}
```

#### 冲突响应（422）

`id` 重复或规范化后网络相同（可同时出现）时返回 HTTP `422`，
`detail` 明确列出冲突 id 与冲突网络分组（分组按该网络首次出现的输入顺序，
组内 id 按输入顺序）：

请求：

```json
{
  "entries": [
    {"id": "x", "cidr": "8.8.8.8"},
    {"id": "y", "cidr": "8.8.8.8/32"},
    {"id": "z", "cidr": "1.1.1.0/24"},
    {"id": "z", "cidr": "2.2.2.0/24"}
  ]
}
```

响应：

```json
{
  "detail": {
    "message": "存在重复的条目 id 或规范化后相同的网络",
    "duplicate_ids": ["z"],
    "duplicate_networks": [
      {"cidr": "8.8.8.8/32", "ids": ["x", "y"]}
    ]
  }
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/cidrs/hierarchy \
  -H 'Content-Type: application/json' \
  -d '{"entries":[
    {"id":"root","cidr":"10.0.0.0/8"},
    {"id":"a","cidr":"10.0.0.0/16"},
    {"id":"b","cidr":"10.1.0.0/16"}
  ]}'
```

### 错误响应（422 Unprocessable Entity）

以下输入均返回 HTTP `422`，错误明细位于 `detail`：

- 空规则集（仅 `/analyze`）：`{"rules": []}` 或缺少 `rules`
- `/compare` 缺少 `left` / `right`，或任一侧缺少 `default_action`
- `/explain` 缺少 `query` 或 `default_action`
- `/cidrs/hierarchy` 条目数不在 1～500、缺少 `entries`、`id` 缺失或为空白
- `/cidrs/hierarchy` 的 **id 重复**或**规范化后网络相同**：
  `detail.duplicate_ids` 列出重复 id，`detail.duplicate_networks`
  按 `{"cidr", "ids"}` 列出每个冲突网络涉及的全部 id
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
不重不漏覆盖，`/cidrs/hierarchy` 的最长严格超网 parent 选择、多 root 与
稳定排序、纯 IP 规范化冲突、重复 id/网络 422 明细、子节点完整覆盖时的空
独占集合，以及用标准库
`ipaddress.collapse_addresses` / `supernet_of` 作为 oracle 的随机属性测试
（无损 + 最少块、parent 关系、独占集合与数量守恒，并与逐地址暴力判定对比）。

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
- **包含层级**：`/cidrs/hierarchy` 先对所有条目做严格 IPv4 解析与
  唯一性校验（id 唯一；规范化后 `(网络地址, 前缀长度)` 唯一，纯 IP 先归一为
  `/32`），再为每个网络选取包含它且前缀最长的输入网络作为唯一严格超网
  parent——同前缀的两个不同网络不可能同时严格包含第三个网络，故最长超网
  不会并列。树与子节点统一按 `(网络地址, 前缀长度, 输入顺序)` 排序。
  独占集合为父区间减去直接子节点区间的并集（直接子节点由“最长超网”
  保证两两不相交），同样走“合并 + 贪心切块”得到最少无损 CIDR；
  每节点满足 `total_addresses = exclusive_address_count + Σ 子节点 total_addresses`。
- **整数运算**：全部基于 32 位无符号整数区间处理，避免字符串/对象开销，
  可正确支持 `0.0.0.0/0` 全空间等边界场景。
