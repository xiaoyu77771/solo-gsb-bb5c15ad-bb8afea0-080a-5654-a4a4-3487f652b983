"""FastAPI 接口测试。"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def post_analyze(rules):
    return client.post("/analyze", json={"rules": rules})


def post_compare(left, right):
    return client.post("/compare", json={"left": left, "right": right})


def test_root_and_health():
    assert client.get("/").status_code == 200
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_full_partial_shadowed():
    resp = post_analyze(
        [
            {"action": "allow", "cidr": "10.0.0.0/8"},
            {"action": "deny", "cidr": "10.1.0.0/16"},
            {"action": "ALLOW", "cidr": "192.168.0.0/16"},
            {"action": "deny", "cidr": "10.0.0.0/7"},
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_count"] == 4
    assert [r["status"] for r in body["rules"]] == [
        "full",
        "shadowed",
        "full",
        "partial",
    ]
    # action 大小写不敏感并规范化
    assert body["rules"][2]["action"] == "allow"
    assert body["rules"][0]["status_label"] == "全生效"
    assert body["rules"][3]["effective_cidrs"] == ["11.0.0.0/8"]
    assert body["summary"] == {
        "full": 2,
        "partial": 1,
        "shadowed": 1,
        "effective_allow_addresses": (1 << 24) + (1 << 16),
        "effective_deny_addresses": 1 << 24,
    }


def test_bare_ip_accepted_as_32():
    resp = post_analyze([{"action": "allow", "cidr": "8.8.8.8"}])
    assert resp.status_code == 200
    rule = resp.json()["rules"][0]
    assert rule["cidr"] == "8.8.8.8/32"
    assert rule["total_addresses"] == 1
    assert rule["status"] == "full"


def test_empty_rules_422():
    assert client.post("/analyze", json={"rules": []}).status_code == 422
    assert client.post("/analyze", json={}).status_code == 422


def test_invalid_cidr_422():
    for bad in ["10.0.0.0/33", "10.0.0.1/8", "garbage", "9.9.9.9/99"]:
        resp = post_analyze([{"action": "allow", "cidr": bad}])
        assert resp.status_code == 422, bad
        assert resp.json()["detail"]


def test_ipv6_422():
    for bad in ["2001:db8::/32", "::1", "fe80::1/64"]:
        assert post_analyze([{"action": "allow", "cidr": bad}]).status_code == 422, bad


def test_bad_action_422():
    assert post_analyze(
        [{"action": "permit", "cidr": "10.0.0.0/8"}]
    ).status_code == 422


def test_missing_field_422():
    assert client.post("/analyze", json={"rules": [{"cidr": "10.0.0.0/8"}]}).status_code == 422
    assert client.post("/analyze", json={"rules": [{"action": "allow"}]}).status_code == 422


def test_non_list_body_422():
    assert client.post("/analyze", json={"rules": "nope"}).status_code == 422


def test_malformed_json_422():
    resp = client.post(
        "/analyze",
        content="{not json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 422


def test_openapi_docs_available():
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


# ---------- /compare ----------

def test_compare_equivalent_empty_sets():
    resp = post_compare(
        {"rules": [], "default_action": "allow"},
        {"rules": [], "default_action": "ALLOW"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"equivalent": True, "differences": []}


def test_compare_default_only_full_space_diff():
    resp = post_compare(
        {"rules": [], "default_action": "deny"},
        {"rules": [], "default_action": "allow"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["equivalent"] is False
    assert body["differences"] == [
        {
            "left_action": "deny",
            "right_action": "allow",
            "address_count": 1 << 32,
            "cidrs": ["0.0.0.0/0"],
        }
    ]


def test_compare_rules_only_one_side():
    resp = post_compare(
        {"rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
         "default_action": "deny"},
        {"rules": [], "default_action": "deny"},
    )
    assert resp.status_code == 200
    assert resp.json()["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 24,
            "cidrs": ["10.0.0.0/8"],
        }
    ]


def test_compare_order_sensitivity_and_bidirectional_groups():
    resp = post_compare(
        {
            "rules": [
                {"action": "allow", "cidr": "10.0.0.0/8"},
                {"action": "deny", "cidr": "10.1.0.0/16"},
            ],
            "default_action": "deny",
        },
        {
            "rules": [
                {"action": "deny", "cidr": "10.1.0.0/16"},
                {"action": "allow", "cidr": "10.0.0.0/8"},
            ],
            "default_action": "deny",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 16,
            "cidrs": ["10.1.0.0/16"],
        }
    ]


def test_compare_shadowed_rule_still_equivalent():
    resp = post_compare(
        {
            "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
            "default_action": "deny",
        },
        {
            "rules": [
                {"action": "allow", "cidr": "10.0.0.0/8"},
                {"action": "deny", "cidr": "10.0.0.1/32"},
            ],
            "default_action": "Deny",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"equivalent": True, "differences": []}


def test_compare_validation_422():
    base = {"rules": [], "default_action": "deny"}

    # 缺少 default_action
    resp = client.post("/compare", json={"left": {"rules": []}, "right": base})
    assert resp.status_code == 422

    # 非法 default_action / action
    assert post_compare(
        {"rules": [], "default_action": "permit"}, base
    ).status_code == 422
    assert post_compare(
        {"rules": [{"action": "permit", "cidr": "10.0.0.0/8"}],
         "default_action": "deny"},
        base,
    ).status_code == 422

    # 非法 CIDR / IPv6（沿用 /analyze 校验）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        resp = post_compare(
            {"rules": [{"action": "allow", "cidr": bad}],
             "default_action": "deny"},
            base,
        )
        assert resp.status_code == 422, bad

    # 缺少一侧 / 请求体为空
    assert client.post("/compare", json={"left": base}).status_code == 422
    assert client.post("/compare", json={}).status_code == 422


# ---------- /explain ----------

def post_explain(rules, default_action, query):
    return client.post(
        "/explain",
        json={"rules": rules, "default_action": default_action, "query": query},
    )


def test_explain_basic_attribution():
    resp = post_explain(
        [
            {"action": "allow", "cidr": "10.0.0.0/16"},
            {"action": "deny", "cidr": "10.0.1.0/24"},
            {"action": "deny", "cidr": "10.2.0.0/16"},
        ],
        "deny",
        "10.0.0.0/8",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "10.0.0.0/8"
    assert body["total_addresses"] == 1 << 24

    attribution = body["attribution"]
    # 规则 1 在 query 内被完全遮蔽 -> 不出现；规则索引升序、默认项最后
    assert [item["rule_index"] for item in attribution] == [0, 2, None]
    assert [item["source"] for item in attribution] == ["rule", "rule", "default"]
    assert attribution[0]["action"] == "allow"
    assert attribution[0]["cidrs"] == ["10.0.0.0/16"]
    assert attribution[1]["action"] == "deny"
    assert attribution[1]["cidrs"] == ["10.2.0.0/16"]
    assert attribution[2]["action"] == "deny"
    # 不重不漏：各项地址数之和等于 query 总数
    assert sum(item["address_count"] for item in attribution) == 1 << 24


def test_explain_bare_ip_query_normalized():
    resp = post_explain(
        [{"action": "ALLOW", "cidr": "8.8.8.0/24"}],
        "Deny",
        "8.8.8.8",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "8.8.8.8/32"
    assert body["total_addresses"] == 1
    # action / default_action 大小写不敏感并规范化
    assert body["attribution"] == [
        {
            "source": "rule",
            "rule_index": 0,
            "action": "allow",
            "address_count": 1,
            "cidrs": ["8.8.8.8/32"],
        }
    ]


def test_explain_empty_rules_all_default():
    resp = post_explain([], "allow", "192.168.0.0/16")
    assert resp.status_code == 200
    assert resp.json()["attribution"] == [
        {
            "source": "default",
            "rule_index": None,
            "action": "allow",
            "address_count": 1 << 16,
            "cidrs": ["192.168.0.0/16"],
        }
    ]


def test_explain_validation_422():
    # 缺少 default_action / query、空请求体
    assert client.post(
        "/explain", json={"rules": [], "query": "10.0.0.0/8"}
    ).status_code == 422
    assert client.post(
        "/explain", json={"rules": [], "default_action": "deny"}
    ).status_code == 422
    assert client.post("/explain", json={}).status_code == 422

    # 非法 query：格式错误、主机位非零、IPv6
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        assert post_explain([], "deny", bad).status_code == 422, bad

    # 非法 default_action / action / 规则 CIDR（沿用现有校验）
    assert post_explain([], "permit", "10.0.0.0/8").status_code == 422
    assert post_explain(
        [{"action": "permit", "cidr": "10.0.0.0/8"}], "deny", "10.0.0.0/8"
    ).status_code == 422
    assert post_explain(
        [{"action": "allow", "cidr": "10.0.0.1/8"}], "deny", "10.0.0.0/8"
    ).status_code == 422


# ---------- /cidrs/hierarchy ----------

def post_hierarchy(entries):
    return client.post("/cidrs/hierarchy", json={"entries": entries})


def test_hierarchy_tree_and_exclusive_cidrs():
    resp = post_hierarchy(
        [
            {"id": "internet", "cidr": "0.0.0.0/0"},
            {"id": "ten", "cidr": "10.0.0.0/8"},
            {"id": "ten16", "cidr": "10.0.0.0/16"},
            {"id": "subnet", "cidr": "10.0.1.0/24"},
            {"id": "lan", "cidr": "192.168.0.0/16"},
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["entry_count"] == 5
    assert body["root_count"] == 1

    internet = body["roots"][0]
    assert internet["cidr"] == "0.0.0.0/0"
    assert internet["total_addresses"] == 1 << 32
    # 直接子节点只有 10/8 与 192.168/16（/16 与 /24 是隔代，不算直接子节点）
    assert [c["id"] for c in internet["children"]] == ["ten", "lan"]
    # 独占 = 全空间减去 10/8 与 192.168/16
    assert internet["exclusive_address_count"] == (
        (1 << 32) - (1 << 24) - (1 << 16)
    )

    ten = internet["children"][0]
    assert ten["total_addresses"] == 1 << 24
    assert [c["id"] for c in ten["children"]] == ["ten16"]
    assert ten["exclusive_address_count"] == (1 << 24) - (1 << 16)

    ten16 = ten["children"][0]
    assert [c["id"] for c in ten16["children"]] == ["subnet"]
    assert ten16["exclusive_address_count"] == (1 << 16) - 256
    # /16 挖掉 10.0.1.0/24 的最少分块，与 /explain 同一套压缩
    assert ten16["exclusive_cidrs"] == [
        "10.0.0.0/24",
        "10.0.2.0/23",
        "10.0.4.0/22",
        "10.0.8.0/21",
        "10.0.16.0/20",
        "10.0.32.0/19",
        "10.0.64.0/18",
        "10.0.128.0/17",
    ]

    subnet = ten16["children"][0]
    assert subnet["exclusive_cidrs"] == ["10.0.1.0/24"]
    assert subnet["exclusive_address_count"] == 256
    assert subnet["children"] == []


def test_hierarchy_roots_sorted_regardless_of_input_order():
    resp = post_hierarchy(
        [
            {"id": "c", "cidr": "192.168.0.0/16"},
            {"id": "b", "cidr": "10.0.0.0/8"},
            {"id": "a", "cidr": "1.0.0.0/8"},
        ]
    )
    assert resp.status_code == 200
    assert [node["id"] for node in resp.json()["roots"]] == ["a", "b", "c"]


def test_hierarchy_bare_ip_normalized():
    resp = post_hierarchy([{"id": "host", "cidr": "8.8.8.8"}])
    assert resp.status_code == 200
    node = resp.json()["roots"][0]
    assert node["cidr"] == "8.8.8.8/32"
    assert node["total_addresses"] == 1


def test_hierarchy_node_fully_covered_by_children():
    resp = post_hierarchy(
        [
            {"id": "p", "cidr": "10.0.0.0/30"},
            {"id": "lo", "cidr": "10.0.0.0/31"},
            {"id": "hi", "cidr": "10.0.0.2/31"},
        ]
    )
    assert resp.status_code == 200
    parent = resp.json()["roots"][0]
    assert parent["exclusive_address_count"] == 0
    assert parent["exclusive_cidrs"] == []


def test_hierarchy_duplicate_network_422_lists_conflicting_ids():
    resp = post_hierarchy(
        [
            {"id": "x", "cidr": "8.8.8.8"},
            {"id": "y", "cidr": "8.8.8.8/32"},
        ]
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "message": "存在重复的条目 id 或规范化后相同的网络",
        "duplicate_ids": [],
        "duplicate_networks": [
            {"cidr": "8.8.8.8/32", "ids": ["x", "y"]}
        ],
    }


def test_hierarchy_duplicate_ids_422():
    resp = post_hierarchy(
        [
            {"id": "dup", "cidr": "1.1.1.0/24"},
            {"id": "dup", "cidr": "2.2.2.0/24"},
            {"id": "other", "cidr": "1.1.1.0/24"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["duplicate_ids"] == ["dup"]
    assert detail["duplicate_networks"] == [
        {"cidr": "1.1.1.0/24", "ids": ["dup", "other"]}
    ]


def test_hierarchy_validation_422():
    # 空列表 / 缺少 entries
    assert client.post("/cidrs/hierarchy", json={"entries": []}).status_code == 422
    assert client.post("/cidrs/hierarchy", json={}).status_code == 422

    # 超过 500 个
    too_many = [
        {"id": str(i), "cidr": f"0.{i // 256}.{i % 256}.0/24"} for i in range(501)
    ]
    assert post_hierarchy(too_many).status_code == 422

    # 500 个仍被接受（id/网络均唯一）
    ok = [
        {"id": str(i), "cidr": f"10.{i // 256}.{i % 256}.0/24"} for i in range(500)
    ]
    assert post_hierarchy(ok).status_code == 200

    # 非法 CIDR / IPv6 沿用既有严格校验
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        assert post_hierarchy([{"id": "a", "cidr": bad}]).status_code == 422, bad

    # id 缺失、空字符串、纯空白、类型错误
    assert post_hierarchy([{"cidr": "10.0.0.0/8"}]).status_code == 422
    assert post_hierarchy([{"id": "", "cidr": "10.0.0.0/8"}]).status_code == 422
    assert post_hierarchy([{"id": "   ", "cidr": "10.0.0.0/8"}]).status_code == 422
    assert client.post(
        "/cidrs/hierarchy",
        json={"entries": "nope"},
    ).status_code == 422
