"""核心分析逻辑的单元测试。"""
import random

import pytest
from ipaddress import IPv4Address, IPv4Network, collapse_addresses, ip_network

from app.analyzer import (
    DuplicateEntriesError,
    InvalidCIDRError,
    MAX_HIERARCHY_ENTRIES,
    V4_SPACE,
    analyze_rules,
    build_cidr_hierarchy,
    build_decision_intervals,
    compare_rule_sets,
    compress_intervals,
    explain_query,
    merge_intervals,
    parse_cidr_v4,
    range_to_cidrs,
    subtract_covered,
)


# ---------- 解析 ----------

def test_parse_basic_cidr():
    start, end, text = parse_cidr_v4("10.0.0.0/8")
    assert start == 10 << 24
    assert end == (10 << 24) + (1 << 24) - 1
    assert text == "10.0.0.0/8"


def test_parse_bare_ip_is_32():
    start, end, text = parse_cidr_v4("192.168.1.1")
    assert start == end
    assert text == "192.168.1.1/32"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "10.0.0.0/33",
        "10.0.0.0/-1",
        "10.0.0",
        "999.0.0.0/8",
        "10.0.0.1/8",  # 主机位非零（strict）
        "not-a-cidr",
        "10.0.0.0/8/8",
        "2001:db8::/32",  # IPv6
        "::1/128",
        "fe80::1",
    ],
)
def test_parse_rejects_invalid_and_ipv6(bad):
    with pytest.raises(InvalidCIDRError):
        parse_cidr_v4(bad)


# ---------- 区间与压缩 ----------

def test_subtract_disjoint_and_overlap():
    covered = [(10, 20), (40, 50)]
    assert subtract_covered((0, 100), covered) == [(0, 9), (21, 39), (51, 100)]
    assert subtract_covered((10, 20), covered) == []
    assert subtract_covered((15, 45), covered) == [(21, 39)]
    assert subtract_covered((0, 5), covered) == [(0, 5)]


def test_merge_includes_adjacent():
    assert merge_intervals([(5, 9), (1, 3), (10, 12), (1, 2)]) == [(1, 3), (5, 12)]
    assert merge_intervals([]) == []


def test_range_to_cidrs_single_block():
    start, end, _ = parse_cidr_v4("10.0.0.0/16")
    assert range_to_cidrs(start, end) == ["10.0.0.0/16"]


def test_range_to_cidrs_full_space_is_slash0():
    assert range_to_cidrs(0, (1 << 32) - 1) == ["0.0.0.0/0"]


def test_compress_split_hole_is_minimal():
    # /8 挖掉开头的 /16，贪心结果必须与手工最优分块一致
    start, end, _ = parse_cidr_v4("10.0.0.0/8")
    pieces = subtract_covered((start, end), [parse_cidr_v4("10.0.0.0/16")[:2]])
    cidrs = compress_intervals(pieces)
    assert cidrs == [
        "10.1.0.0/16",
        "10.2.0.0/15",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9",
    ]
    # 无损：数量守恒
    assert sum(IPv4Network(c).num_addresses for c in cidrs) == (1 << 24) - (1 << 16)


# ---------- 规则分析 ----------

def test_full_partial_shadowed_and_totals():
    result = analyze_rules(
        [
            ("allow", "10.0.0.0/8"),  # full, 2^24
            ("deny", "10.1.0.0/16"),  # shadowed
            ("allow", "192.168.0.0/16"),  # full, 2^16
            ("deny", "10.0.0.0/7"),  # partial: 只 11.0.0.0/8 生效
        ]
    )
    statuses = [r["status"] for r in result["rules"]]
    assert statuses == ["full", "shadowed", "full", "partial"]

    last = result["rules"][3]
    assert last["effective_addresses"] == 1 << 24
    assert last["covered_addresses"] == 1 << 24
    assert last["effective_cidrs"] == ["11.0.0.0/8"]

    summary = result["summary"]
    assert summary["full"] == 2
    assert summary["partial"] == 1
    assert summary["shadowed"] == 1
    assert summary["effective_allow_addresses"] == (1 << 24) + (1 << 16)
    assert summary["effective_deny_addresses"] == 1 << 24


def test_cross_action_shadowing():
    # 先前的 allow 同样遮蔽后面的 deny
    result = analyze_rules([("allow", "0.0.0.0/0"), ("deny", "8.8.8.8/32")])
    assert result["rules"][1]["status"] == "shadowed"
    assert result["rules"][1]["effective_cidrs"] == []
    assert result["summary"]["effective_deny_addresses"] == 0
    assert result["summary"]["effective_allow_addresses"] == 1 << 32


def test_order_matters_and_duplicates_shadow():
    first = analyze_rules([("allow", "10.1.0.0/16"), ("deny", "10.0.0.0/8")])
    second = analyze_rules([("deny", "10.0.0.0/8"), ("allow", "10.1.0.0/16")])
    assert first["rules"][1]["status"] == "partial"
    assert second["rules"][1]["status"] == "shadowed"

    dup = analyze_rules([("allow", "1.2.3.0/24"), ("allow", "1.2.3.0/24")])
    assert dup["rules"][1]["status"] == "shadowed"
    # 重复地址不重复计入
    assert dup["summary"]["effective_allow_addresses"] == 256


def test_empty_rules_rejected():
    with pytest.raises(ValueError):
        analyze_rules([])


def test_adjacent_fragments_merge_before_compress():
    # /30 中先遮蔽末端两个地址，剩余 .0/.1 相邻且 /31 对齐 -> 必须合并为单个 /31
    # （若不在压缩前合并相邻碎片，会退化为两个 /32）
    result = analyze_rules(
        [
            ("deny", "10.0.0.2/31"),
            ("allow", "10.0.0.0/30"),
        ]
    )
    last = result["rules"][1]
    assert last["effective_cidrs"] == ["10.0.0.0/31"]
    assert last["status"] == "partial"

    # 相邻但不对齐的两个地址（.1/.2）无法合并，最优仍是两个 /32
    result2 = analyze_rules(
        [
            ("deny", "10.0.0.0/32"),
            ("deny", "10.0.0.3/32"),
            ("allow", "10.0.0.0/30"),
        ]
    )
    assert result2["rules"][2]["effective_cidrs"] == [
        "10.0.0.1/32",
        "10.0.0.2/32",
    ]


# ---------- 属性测试：与 ipaddress 标准库 oracle 对比 ----------

def test_random_rules_oracle():
    rng = random.Random(20260918)
    universe = list(ip_network("10.0.0.0/16").subnets(new_prefix=24))  # 256 个 /24
    for _ in range(30):
        picked = rng.sample(universe, k=rng.randint(1, 12))
        actions = [rng.choice(["allow", "deny"]) for _ in picked]

        result = analyze_rules([(a, str(net)) for a, net in zip(actions, picked)])

        claimed: set = set()
        seen_effective: set = set()
        for net, res in zip(picked, result["rules"]):
            remaining = set(net) - claimed
            # 标准库给出的最少 CIDR 分块
            expected = [str(c) for c in collapse_addresses(remaining)]
            assert res["effective_cidrs"] == expected

            rebuilt = set()
            for c in res["effective_cidrs"]:
                rebuilt |= set(ip_network(c))
            assert rebuilt == remaining  # 无损
            assert not rebuilt & seen_effective  # 生效集合两两不相交
            seen_effective |= rebuilt
            claimed |= set(net)

        summary = result["summary"]
        assert summary["effective_allow_addresses"] == sum(
            r["effective_addresses"] for r in result["rules"] if r["action"] == "allow"
        )
        assert summary["effective_deny_addresses"] == sum(
            r["effective_addresses"] for r in result["rules"] if r["action"] == "deny"
        )
        assert (
            sum(r["effective_addresses"] for r in result["rules"])
            == len(seen_effective)
        )


# ---------- 规则集等价性比较 ----------

def test_decision_partition_covers_full_space_without_enumeration():
    rules = [("allow", "10.0.0.0/8"), ("deny", "10.1.0.0/16")]
    partition = build_decision_intervals(rules, "deny")

    # 有序、首尾相接、数量守恒：完整覆盖整个 IPv4 空间
    assert partition[0][0] == 0
    assert partition[-1][1] == V4_SPACE - 1
    assert sum(end - start + 1 for start, end, _ in partition) == V4_SPACE
    for (_, prev_end, _), (next_start, _, _) in zip(partition, partition[1:]):
        assert next_start == prev_end + 1

    # 10.1/16 先命中 allow；其余 10/8 为 allow；外部为默认 deny
    actions = {action for _, _, action in partition}
    assert actions == {"allow", "deny"}
    assert build_decision_intervals(rules, "deny")[0][2] == "deny"

    # 被完全遮蔽的规则不出现在最终判定中
    shadowed = [("allow", "10.0.0.0/8"), ("deny", "10.1.0.0/16")]
    assert build_decision_intervals(shadowed, "deny") == build_decision_intervals(
        [("allow", "10.0.0.0/8")], "deny"
    )


def test_compare_identical_and_shadowed_rules_equivalent():
    rules = [("allow", "10.0.0.0/8"), ("deny", "10.1.0.0/16")]
    # 相同规则集必然等价
    assert compare_rule_sets(rules, "deny", rules, "deny")["equivalent"]
    # 追加一条被完全遮蔽的规则不改变最终判定
    with_extra = [*rules, ("allow", "10.1.0.0/24")]
    assert compare_rule_sets(rules, "deny", with_extra, "deny") == {
        "equivalent": True,
        "differences": [],
    }
    # 空规则集 + 相同默认动作同样等价
    assert compare_rule_sets([], "allow", [], "allow") == {
        "equivalent": True,
        "differences": [],
    }


def test_compare_order_matters_first_match_wins():
    # 与 /analyze 一致的顺序敏感性：10.1/16 左侧 allow、右侧 deny
    left = [("allow", "10.0.0.0/8"), ("deny", "10.1.0.0/16")]
    right = [("deny", "10.1.0.0/16"), ("allow", "10.0.0.0/8")]
    result = compare_rule_sets(left, "deny", right, "deny")
    assert result["equivalent"] is False
    assert result["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 16,
            "cidrs": ["10.1.0.0/16"],
        }
    ]


def test_compare_default_action_drives_full_space():
    # 两侧都没有规则，默认动作不同 -> 整个 IPv4 空间不同
    result = compare_rule_sets([], "allow", [], "deny")
    assert result == {
        "equivalent": False,
        "differences": [
            {
                "left_action": "allow",
                "right_action": "deny",
                "address_count": V4_SPACE,
                "cidrs": ["0.0.0.0/0"],
            }
        ],
    }

    # 左 allow 0/0（default deny 不生效）与右空规则 default allow 等价
    assert compare_rule_sets(
        [("allow", "0.0.0.0/0")], "deny", [], "allow"
    )["equivalent"]


def test_compare_bidirectional_groups_and_minimal_compression():
    left = [("allow", "10.0.0.0/8"), ("deny", "11.0.0.0/8")]
    right = [("deny", "10.0.0.0/8"), ("allow", "11.0.0.0/8")]
    result = compare_rule_sets(left, "deny", right, "allow")

    groups = {
        (g["left_action"], g["right_action"]): g for g in result["differences"]
    }
    assert set(groups) == {("allow", "deny"), ("deny", "allow")}
    assert groups[("allow", "deny")]["cidrs"] == ["10.0.0.0/8"]
    assert groups[("allow", "deny")]["address_count"] == 1 << 24
    # 11/8 双向 + default 在其余空间 deny/allow，压缩必须与标准库挖洞结果一致
    rest = groups[("deny", "allow")]
    expected = [
        str(c)
        for c in collapse_addresses(
            list(ip_network("0.0.0.0/0").address_exclude(ip_network("10.0.0.0/8")))
        )
    ]
    assert rest["cidrs"] == expected
    assert rest["address_count"] == V4_SPACE - (1 << 24)
    assert sum(g["address_count"] for g in result["differences"]) == V4_SPACE


def test_compare_rejects_invalid_inputs():
    with pytest.raises(InvalidCIDRError):
        compare_rule_sets([("allow", "10.0.0.1/8")], "deny", [], "deny")
    with pytest.raises(InvalidCIDRError):
        compare_rule_sets([], "deny", [("allow", "2001:db8::/32")], "deny")
    with pytest.raises(ValueError):
        compare_rule_sets([("permit", "10.0.0.0/8")], "deny", [], "deny")
    with pytest.raises(ValueError):
        compare_rule_sets([], "PERMIT", [], "deny")


def test_compare_random_rules_oracle():
    """与逐地址暴力 oracle 对比（差异仅可能出现在 10.0.0.0/24 内）。"""
    rng = random.Random(20260918)
    universe = [str(n) for n in ip_network("10.0.0.0/24").subnets(new_prefix=30)]
    base = int(ip_network("10.0.0.0/24").network_address)
    outside_nets = list(
        ip_network("0.0.0.0/0").address_exclude(ip_network("10.0.0.0/24"))
    )

    def make_rules():
        return [
            (rng.choice(["allow", "deny"]), rng.choice(universe))
            for _ in range(rng.randint(0, 10))
        ]

    def decide(parsed, default, value):
        for action, (start, end, _) in parsed:
            if start <= value <= end:
                return action
        return default

    for _ in range(200):
        left_raw, right_raw = make_rules(), make_rules()
        left_default = rng.choice(["allow", "deny"])
        right_default = rng.choice(["allow", "deny"])
        left_parsed = [(a, parse_cidr_v4(c)) for a, c in left_raw]
        right_parsed = [(a, parse_cidr_v4(c)) for a, c in right_raw]

        result = compare_rule_sets(left_raw, left_default, right_raw, right_default)

        expected: dict[tuple[str, str], set] = {}
        for value in range(base, base + 256):
            la = decide(left_parsed, left_default, value)
            ra = decide(right_parsed, right_default, value)
            if la != ra:
                expected.setdefault((la, ra), set()).add(value)

        # /24 之外只有 default 可能不同
        external = left_default != right_default
        got = {
            (g["left_action"], g["right_action"]): g for g in result["differences"]
        }
        expected_keys = set(expected) | (
            {(left_default, right_default)} if external else set()
        )
        assert set(got) == expected_keys

        for key, addresses in expected.items():
            group = got[key]
            if external and key == (left_default, right_default):
                # 该组同时包含 /24 外的 default 差异，稍后统一校验
                continue
            assert group["address_count"] == len(addresses)
            assert group["cidrs"] == [
                str(c)
                for c in collapse_addresses(
                    [ip_network(f"{IPv4Address(value)}/32") for value in addresses]
                )
            ]
        if external:
            group = got[(left_default, right_default)]
            within = expected.get((left_default, right_default), set())
            within_nets = [
                ip_network(f"{IPv4Address(value)}/32") for value in within
            ]
            assert group["cidrs"] == [
                str(c) for c in collapse_addresses([*within_nets, *outside_nets])
            ]
            assert group["address_count"] == len(within) + V4_SPACE - 256

        assert result["equivalent"] == (not expected and not external)


# ---------- 地址空间裁决归因（/explain） ----------

def test_explain_basic_attribution_and_default_last():
    result = explain_query(
        [
            ("allow", "10.0.0.0/16"),
            ("deny", "10.0.1.0/24"),  # 被规则 0 完全遮蔽
            ("deny", "10.2.0.0/16"),
        ],
        "deny",
        "10.0.0.0/8",
    )
    assert result["query"] == "10.0.0.0/8"
    assert result["total_addresses"] == 1 << 24

    attribution = result["attribution"]
    # 规则 1 在 query 内完全遮蔽 -> 不出现；规则索引升序、默认项最后
    assert [item["rule_index"] for item in attribution] == [0, 2, None]
    assert [item["source"] for item in attribution] == ["rule", "rule", "default"]
    assert attribution[0] == {
        "source": "rule",
        "rule_index": 0,
        "action": "allow",
        "address_count": 1 << 16,
        "cidrs": ["10.0.0.0/16"],
    }
    assert attribution[1] == {
        "source": "rule",
        "rule_index": 2,
        "action": "deny",
        "address_count": 1 << 16,
        "cidrs": ["10.2.0.0/16"],
    }
    # 默认项：10.0.0.0/8 挖掉 10.0.0.0/16 与 10.2.0.0/16 后的剩余
    default_item = attribution[2]
    assert default_item["action"] == "deny"
    assert default_item["cidrs"] == [
        "10.1.0.0/16",
        "10.3.0.0/16",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9",
    ]
    # 不重不漏：各项地址数之和等于 query 总数
    assert sum(item["address_count"] for item in attribution) == 1 << 24


def test_explain_bare_ip_query_and_action_hit():
    result = explain_query(
        [("allow", "8.8.8.0/24"), ("deny", "8.8.8.8")],
        "allow",
        "8.8.8.8",
    )
    assert result["query"] == "8.8.8.8/32"
    assert result["total_addresses"] == 1
    # 首条匹配生效：8.8.8.8 先命中规则 0
    assert result["attribution"] == [
        {
            "source": "rule",
            "rule_index": 0,
            "action": "allow",
            "address_count": 1,
            "cidrs": ["8.8.8.8/32"],
        }
    ]


def test_explain_empty_rules_all_default():
    result = explain_query([], "allow", "192.168.0.0/16")
    assert result["attribution"] == [
        {
            "source": "default",
            "rule_index": None,
            "action": "allow",
            "address_count": 1 << 16,
            "cidrs": ["192.168.0.0/16"],
        }
    ]


def test_explain_full_coverage_has_no_default_item():
    result = explain_query(
        [("deny", "10.0.0.0/8")],
        "allow",
        "10.0.0.0/8",
    )
    assert result["attribution"] == [
        {
            "source": "rule",
            "rule_index": 0,
            "action": "deny",
            "address_count": 1 << 24,
            "cidrs": ["10.0.0.0/8"],
        }
    ]


def test_explain_ignores_rules_outside_query():
    result = explain_query(
        [
            ("allow", "192.168.0.0/16"),  # 与 query 不相交
            ("deny", "10.1.0.0/16"),
        ],
        "deny",
        "10.0.0.0/8",
    )
    assert [item["rule_index"] for item in result["attribution"]] == [1, None]
    assert result["attribution"][0]["cidrs"] == ["10.1.0.0/16"]
    assert result["attribution"][1]["cidrs"] == [
        "10.0.0.0/16",
        "10.2.0.0/15",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9",
    ]


def test_explain_rejects_invalid_inputs():
    with pytest.raises(InvalidCIDRError):
        explain_query([], "deny", "10.0.0.1/8")
    with pytest.raises(InvalidCIDRError):
        explain_query([], "deny", "2001:db8::/32")
    with pytest.raises(InvalidCIDRError):
        explain_query([("allow", "garbage")], "deny", "10.0.0.0/8")
    with pytest.raises(ValueError):
        explain_query([("permit", "10.0.0.0/8")], "deny", "10.0.0.0/8")
    with pytest.raises(ValueError):
        explain_query([], "PERMIT", "10.0.0.0/8")


def test_explain_random_rules_oracle():
    """与逐地址暴力 oracle 对比：归属、覆盖不重不漏、最少 CIDR。"""
    rng = random.Random(20260918)
    universe = [str(n) for n in ip_network("10.0.0.0/24").subnets(new_prefix=30)]
    q_start, q_end, _ = parse_cidr_v4("10.0.0.0/24")

    for _ in range(200):
        rules = [
            (rng.choice(["allow", "deny"]), rng.choice(universe))
            for _ in range(rng.randint(0, 10))
        ]
        default = rng.choice(["allow", "deny"])
        parsed = [(a, parse_cidr_v4(c)) for a, c in rules]

        result = explain_query(rules, default, "10.0.0.0/24")
        assert result["query"] == "10.0.0.0/24"
        assert result["total_addresses"] == 256

        # 逐地址暴力判定归属：首条命中的规则索引，否则 default
        expected: dict[object, set] = {}
        for value in range(q_start, q_end + 1):
            owner: object = None
            for index, (_, (start, end, _)) in enumerate(parsed):
                if start <= value <= end:
                    owner = index
                    break
            expected.setdefault(owner, set()).add(value)

        attribution = result["attribution"]
        # 规则项按索引升序、默认项最后
        keys = [item["rule_index"] for item in attribution]
        rule_keys = [k for k in keys if k is not None]
        assert rule_keys == sorted(rule_keys)
        if None in keys:
            assert keys[-1] is None
        assert set(keys) == set(expected)

        for item in attribution:
            owner = item["rule_index"]
            addresses = expected[owner]
            if owner is None:
                assert item["source"] == "default"
                assert item["action"] == default
            else:
                assert item["source"] == "rule"
                assert item["action"] == parsed[owner][0]
            assert item["address_count"] == len(addresses)
            # 与标准库 oracle 对比：无损且块数最少
            assert item["cidrs"] == [
                str(c)
                for c in collapse_addresses(
                    [ip_network(f"{IPv4Address(v)}/32") for v in addresses]
                )
            ]

        # 不重不漏覆盖整个 query
        assert sum(item["address_count"] for item in attribution) == 256


# ---------- CIDR 包含层级（/cidrs/hierarchy） ----------

def walk_nodes(tree):
    """按深度优先顺序产出树中的全部节点。"""
    for root in tree["roots"]:
        stack = [root]
        while stack:
            node = stack.pop()
            yield node
            stack.extend(reversed(node["children"]))


def test_hierarchy_parent_is_longest_strict_supernet():
    result = build_cidr_hierarchy(
        [
            ("internet", "0.0.0.0/0"),
            ("ten", "10.0.0.0/8"),
            ("ten16", "10.0.0.0/16"),
            ("subnet", "10.0.1.0/24"),  # parent 必须是 ten16 而非 ten
            ("lan", "192.168.0.0/16"),
        ]
    )
    assert result["entry_count"] == 5
    assert result["root_count"] == 1
    internet = result["roots"][0]
    assert internet["id"] == "internet"
    assert internet["cidr"] == "0.0.0.0/0"
    ten, lan = internet["children"]
    assert ten["id"] == "ten"
    assert lan["id"] == "lan"
    ten16 = ten["children"][0]
    assert ten16["id"] == "ten16"
    assert ten16["children"][0]["id"] == "subnet"


def test_hierarchy_totals_exclusive_and_minimal_cidrs():
    result = build_cidr_hierarchy(
        [
            ("ten", "10.0.0.0/8"),
            ("a", "10.0.0.0/16"),
            ("b", "10.1.0.0/16"),
        ]
    )
    ten = result["roots"][0]
    # 两个 /16 挖掉 10.0.0.0/15 后剩余部分，与标准库挖洞结果一致
    expected = [
        str(c)
        for c in collapse_addresses(
            list(ip_network("10.0.0.0/8").address_exclude(ip_network("10.0.0.0/15")))
        )
    ]
    assert ten["exclusive_cidrs"] == expected
    assert ten["exclusive_address_count"] == (1 << 24) - 2 * (1 << 16)
    assert ten["total_addresses"] == 1 << 24
    for child in ten["children"]:
        assert child["exclusive_cidrs"] == [child["cidr"]]
        assert child["exclusive_address_count"] == 1 << 16
        assert child["children"] == []


def test_hierarchy_node_with_no_exclusive_addresses():
    # 单个 /30 被两个 /31 完整覆盖 -> 父节点独占地址数为 0、cidr 为空
    result = build_cidr_hierarchy(
        [
            ("p", "10.0.0.0/30"),
            ("lo", "10.0.0.0/31"),
            ("hi", "10.0.0.2/31"),
        ]
    )
    parent = result["roots"][0]
    assert parent["id"] == "p"
    assert parent["exclusive_address_count"] == 0
    assert parent["exclusive_cidrs"] == []
    assert [c["id"] for c in parent["children"]] == ["lo", "hi"]


def test_hierarchy_multiple_roots_sorted_by_network():
    # 输入顺序故意打乱，root 与子节点都按 (网络地址, 前缀长度) 排列
    result = build_cidr_hierarchy(
        [
            ("c", "192.168.0.0/16"),
            ("b", "10.0.0.0/8"),
            ("a", "1.0.0.0/8"),
        ]
    )
    assert result["root_count"] == 3
    assert [node["id"] for node in result["roots"]] == ["a", "b", "c"]


def test_hierarchy_stable_order_uses_input_sequence_as_tiebreak():
    # 同一父节点下互不包含的多个 /24，按网络地址排列；等长等地址不会出现，
    # 这里验证同网络不同前缀（不同节点）不会冲突且顺序确定
    result = build_cidr_hierarchy(
        [
            ("second", "10.0.1.0/24"),
            ("first", "10.0.0.0/24"),
            ("parent", "10.0.0.0/16"),
        ]
    )
    parent = result["roots"][0]
    assert parent["id"] == "parent"
    assert [c["id"] for c in parent["children"]] == ["first", "second"]


def test_hierarchy_bare_ip_normalized_to_32():
    result = build_cidr_hierarchy([("host", "8.8.8.8")])
    node = result["roots"][0]
    assert node["cidr"] == "8.8.8.8/32"
    assert node["total_addresses"] == 1
    assert node["exclusive_address_count"] == 1
    assert node["exclusive_cidrs"] == ["8.8.8.8/32"]


def test_hierarchy_duplicate_ids_and_networks_raise():
    with pytest.raises(DuplicateEntriesError) as exc:
        build_cidr_hierarchy(
            [
                ("dup", "1.1.1.0/24"),
                ("dup", "2.2.2.0/24"),
                ("other", "1.1.1.0/24"),
            ]
        )
    assert exc.value.duplicate_ids == ["dup"]
    assert exc.value.duplicate_networks == [
        {"cidr": "1.1.1.0/24", "ids": ["dup", "other"]}
    ]

    # 纯 IP 与 /32 规范化后网络相同
    with pytest.raises(DuplicateEntriesError) as exc:
        build_cidr_hierarchy([("x", "8.8.8.8"), ("y", "8.8.8.8/32")])
    assert exc.value.duplicate_networks == [
        {"cidr": "8.8.8.8/32", "ids": ["x", "y"]}
    ]

    # 多个冲突网络组按网络首次出现顺序返回
    with pytest.raises(DuplicateEntriesError) as exc:
        build_cidr_hierarchy(
            [
                ("a", "3.0.0.0/8"),
                ("b", "2.0.0.0/8"),
                ("a2", "3.0.0.0/8"),
                ("b2", "2.0.0.0/8"),
            ]
        )
    assert exc.value.duplicate_networks == [
        {"cidr": "3.0.0.0/8", "ids": ["a", "a2"]},
        {"cidr": "2.0.0.0/8", "ids": ["b", "b2"]},
    ]


def test_hierarchy_rejects_invalid_inputs():
    with pytest.raises(ValueError):
        build_cidr_hierarchy([])
    with pytest.raises(ValueError):
        build_cidr_hierarchy(
            [
                (str(i), f"0.{i // 256}.{i % 256}.0/24")
                for i in range(MAX_HIERARCHY_ENTRIES + 1)
            ]
        )
    with pytest.raises(InvalidCIDRError):
        build_cidr_hierarchy([("a", "10.0.0.1/8")])
    with pytest.raises(InvalidCIDRError):
        build_cidr_hierarchy([("a", "2001:db8::/32")])
    with pytest.raises(ValueError):
        build_cidr_hierarchy([("", "10.0.0.0/8")])
    with pytest.raises(ValueError):
        build_cidr_hierarchy([("   ", "10.0.0.0/8")])


def test_hierarchy_random_oracle():
    """随机集合上用 ipaddress 校验：parent 关系、排序、独占集合与数量守恒。"""
    rng = random.Random(20260918)
    # 在 10.0.0.0/14 内取各前缀长度的网络，保证存在多层包含关系
    candidates: list[IPv4Network] = []
    for net in ip_network("10.0.0.0/14").subnets(new_prefix=16):
        candidates.append(net)
    for net in ip_network("10.0.0.0/14").subnets(new_prefix=20):
        candidates.append(net)
    for net in ip_network("10.0.0.0/14").subnets(new_prefix=24):
        candidates.append(net)

    for _ in range(60):
        picked = rng.sample(candidates, k=rng.randint(1, 20))
        # 过滤掉规范化后重复的选择（不同前缀不可能重复，此处仅防御）
        unique_nets: list[IPv4Network] = []
        for net in picked:
            if net not in unique_nets:
                unique_nets.append(net)
        entries = [(f"n{i}", str(net)) for i, net in enumerate(unique_nets)]
        result = build_cidr_hierarchy(entries)
        nets_by_id = {f"n{i}": net for i, net in enumerate(unique_nets)}

        nodes = list(walk_nodes(result))
        assert len(nodes) == len(unique_nets)

        # 递归 oracle 校验
        def check(node, expected_parent_net):
            net = nets_by_id[node["id"]]
            children_nets = [nets_by_id[c["id"]] for c in node["children"]]

            # parent 必须是包含本网络的最长前缀严格超网
            # 注意 ipaddress 的 supernet_of 对同网络自身也返回 True，需排除
            strict_supers = [
                n for n in unique_nets if n.supernet_of(net) and n.prefixlen < net.prefixlen
            ]
            if expected_parent_net is None:
                assert strict_supers == []
            else:
                assert expected_parent_net.supernet_of(net)
                longest = max(strict_supers, key=lambda n: n.prefixlen)
                assert longest == expected_parent_net

            # 子节点必须是本网络的严格子网，且两两不相交
            for child in children_nets:
                assert net.supernet_of(child)
            for i, left in enumerate(children_nets):
                for right in children_nets[i + 1 :]:
                    assert not left.overlaps(right)

            # 独占集合 = 本网络减去全部直接子节点的并集
            covered: set = set()
            for child in children_nets:
                covered |= set(child)
            exclusive_set = set(net) - covered
            assert node["total_addresses"] == net.num_addresses
            assert node["exclusive_address_count"] == len(exclusive_set)
            expected_cidrs = [str(c) for c in collapse_addresses(list(exclusive_set))]
            assert node["exclusive_cidrs"] == expected_cidrs

            # 子节点按 (网络地址, 前缀长度, 输入顺序) 排列
            child_keys = [
                (int(n.network_address), n.prefixlen, unique_nets.index(n))
                for n in children_nets
            ]
            assert child_keys == sorted(child_keys)

            for child in node["children"]:
                check(child, net)

        # root 校验
        root_nets = [nets_by_id[r["id"]] for r in result["roots"]]
        root_keys = [
            (int(n.network_address), n.prefixlen, unique_nets.index(n))
            for n in root_nets
        ]
        assert root_keys == sorted(root_keys)
        for root in result["roots"]:
            check(root, None)

        # 数量守恒：扁平条目与树中节点的 total_addresses 各自求和一致
        total_flat = sum(net.num_addresses for net in unique_nets)
        assert total_flat == sum(node["total_addresses"] for node in nodes)

        # 每个 root：total == 自身独占 + 全部后代 total 之和
        def subtree_sum(node):
            return node["exclusive_address_count"] + sum(
                subtree_sum(child) for child in node["children"]
            )

        for root in result["roots"]:
            assert subtree_sum(root) == root["total_addresses"]
