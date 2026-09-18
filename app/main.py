"""FastAPI 应用：IPv4 CIDR 遮蔽分析与规则集等价性比较 API。"""
from __future__ import annotations

from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, field_validator

from .analyzer import (
    DuplicateEntriesError,
    InvalidCIDRError,
    analyze_rules,
    build_cidr_hierarchy,
    compare_rule_sets,
    explain_query,
    parse_cidr_v4,
)

app = FastAPI(
    title="IPv4 遮蔽分析 API",
    description=(
        "接收有序的 allow/deny CIDR 规则，计算每条规则未被此前规则覆盖的"
        "地址集合，按 **全生效 (full)** / **部分遮蔽 (partial)** / "
        "**完全遮蔽 (shadowed)** 分类，并将剩余集合无损压缩为数量最少的 CIDR；"
        "也可通过 /compare 比较两组规则在整个 IPv4 空间上的最终判定是否等价，"
        "或通过 /explain 解释一段地址空间由哪条规则或默认动作最终裁决；"
        "还可通过 /cidrs/hierarchy 分析一组 CIDR 的包含层级（唯一最长超网为 parent）"
        "及每个网段扣除直接子节点后的独占地址集合。"
    ),
    version="1.3.0",
)


class Rule(BaseModel):
    """单条规则：动作 + IPv4 CIDR。"""

    action: Literal["allow", "deny"] = Field(
        ..., description="动作，仅允许 allow 或 deny（大小写不敏感）"
    )
    cidr: str = Field(
        ...,
        description="IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )

    @field_validator("action", mode="before")
    @classmethod
    def normalize_action(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]


class AnalyzeRequest(BaseModel):
    """分析请求：有序规则列表，至少 1 条。"""

    rules: list[Rule] = Field(..., min_length=1, description="有序规则列表（按序处理）")


class RuleResult(BaseModel):
    index: int = Field(..., description="规则在输入中的序号（从 0 开始）")
    action: Literal["allow", "deny"]
    cidr: str = Field(..., description="规范化后的规则 CIDR")
    status: Literal["full", "partial", "shadowed"]
    status_label: str = Field(..., description="状态中文说明")
    total_addresses: int
    covered_addresses: int = Field(..., description="被此前规则遮蔽的地址数")
    effective_addresses: int = Field(..., description="本规则实际生效的地址数")
    effective_cidrs: list[str] = Field(
        ..., description="生效地址集合无损压缩后的最少 CIDR 列表（空表示完全遮蔽）"
    )


class Summary(BaseModel):
    full: int
    partial: int
    shadowed: int
    effective_allow_addresses: int = Field(..., description="汇总生效的 allow 地址数")
    effective_deny_addresses: int = Field(..., description="汇总生效的 deny 地址数")


class AnalyzeResponse(BaseModel):
    rule_count: int
    rules: list[RuleResult]
    summary: Summary


class RuleSet(BaseModel):
    """一侧规则集：有序规则列表 + 未命中时的默认动作。"""

    rules: list[Rule] = Field(
        default_factory=list, description="有序规则列表（按序处理），可为空"
    )
    default_action: Literal["allow", "deny"] = Field(
        ...,
        description="未命中任何规则时的默认动作（大小写不敏感）",
    )

    @field_validator("default_action", mode="before")
    @classmethod
    def normalize_default_action(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value


class CompareRequest(BaseModel):
    """比较请求：左右两侧规则集及其默认动作。"""

    left: RuleSet
    right: RuleSet


class DifferenceGroup(BaseModel):
    left_action: Literal["allow", "deny"]
    right_action: Literal["allow", "deny"]
    address_count: int = Field(..., description="该判定组合覆盖的地址数")
    cidrs: list[str] = Field(
        ...,
        description="该组地址集合无损压缩后的最少 CIDR 列表",
    )


class CompareResponse(BaseModel):
    equivalent: bool = Field(
        ..., description="两侧在整个 IPv4 空间上的最终判定是否完全一致"
    )
    differences: list[DifferenceGroup] = Field(
        ...,
        description="判定不同的地址分组（按 left_action/right_action）；等价时为空",
    )


class ExplainRequest(RuleSet):
    """解释请求：有序规则列表 + 默认动作 + 单个待解释的 query CIDR。"""

    query: str = Field(
        ...,
        description="待解释的 IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]


class AttributionItem(BaseModel):
    source: Literal["rule", "default"] = Field(
        ..., description="裁决来源：rule 表示命中规则，default 表示走默认动作"
    )
    rule_index: int | None = Field(
        ..., description="命中规则在输入中的序号（从 0 开始）；默认项为 null"
    )
    action: Literal["allow", "deny"]
    address_count: int = Field(..., description="该项覆盖的地址数")
    cidrs: list[str] = Field(
        ..., description="该项地址集合无损压缩后的最少 CIDR 列表"
    )


class ExplainResponse(BaseModel):
    query: str = Field(..., description="规范化后的 query CIDR")
    total_addresses: int = Field(..., description="query 覆盖的地址总数")
    attribution: list[AttributionItem] = Field(
        ...,
        description=(
            "归因列表：按规则索引升序、默认项最后；所有项不重不漏覆盖 query"
        ),
    )


class CidrEntry(BaseModel):
    """单个 CIDR 条目：唯一 id + 严格 IPv4 CIDR。"""

    id: str = Field(
        ...,
        min_length=1,
        description="条目唯一标识（非空字符串）；重复或仅空白均返回 422",
    )
    cidr: str = Field(
        ...,
        description="IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("id 不能为空白字符串")
        return value

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]


class HierarchyRequest(BaseModel):
    """层级分析请求：1～500 个带唯一 id 的 CIDR 条目。"""

    entries: list[CidrEntry] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="CIDR 条目列表（1～500 个）；id 必须唯一，规范化后网络不能重复",
    )


class HierarchyNode(BaseModel):
    """层级树节点：本节点信息 + 直接子节点（递归）。"""

    id: str = Field(..., description="条目 id")
    cidr: str = Field(..., description="规范化后的 CIDR")
    total_addresses: int = Field(..., description="该网段覆盖的地址总数")
    exclusive_address_count: int = Field(
        ...,
        description="本网段扣除全部直接子节点地址并集后独占的地址数",
    )
    exclusive_cidrs: list[str] = Field(
        ...,
        description="独占地址集合无损压缩后的最少 CIDR 列表（无独占地址时为空）",
    )
    children: list["HierarchyNode"] = Field(
        ...,
        description=(
            "直接子节点（以本节点为唯一最长严格超网的网段）；"
            "按网络地址、前缀长度、输入顺序稳定排列"
        ),
    )


HierarchyNode.model_rebuild()


class HierarchyResponse(BaseModel):
    entry_count: int = Field(..., description="输入条目总数")
    root_count: int = Field(..., description="根节点（无严格超网）数量")
    roots: list[HierarchyNode] = Field(
        ...,
        description=(
            "根节点列表；整棵树按网络地址、前缀长度、输入顺序稳定排列"
        ),
    )


@app.get("/", tags=["meta"])
def root() -> dict:
    """服务信息。"""
    return {
        "service": "ipv4-shadow-analyzer",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "health": "/health",
    }


@app.get("/health", tags=["meta"])
def health() -> dict:
    """健康检查。"""
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["analyze"],
    summary="分析有序 allow/deny 规则的遮蔽情况",
)
def analyze(request: AnalyzeRequest) -> dict:
    """按顺序计算每条规则未被此前规则覆盖的地址集合并分类。

    非法 CIDR、IPv6、空规则集均返回 **422 Unprocessable Entity**。
    """
    # analyzer 再做一次防御性校验（该模块也可独立使用）
    try:
        return analyze_rules([(r.action, r.cidr) for r in request.rules])
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/compare",
    response_model=CompareResponse,
    tags=["compare"],
    summary="比较两组有序规则在整个 IPv4 空间上的最终判定是否等价",
)
def compare(request: CompareRequest) -> dict:
    """两侧均沿用 /analyze 的 CIDR 校验与“首条匹配规则生效”顺序。

    未命中任何规则的地址取各自 ``default_action``；判定不同的地址按
    left_action/right_action 分组，返回地址数与无损压缩后的最少 CIDR。
    基于区间归并计算，不逐地址枚举。
    """
    try:
        return compare_rule_sets(
            [(r.action, r.cidr) for r in request.left.rules],
            request.left.default_action,
            [(r.action, r.cidr) for r in request.right.rules],
            request.right.default_action,
        )
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/explain",
    response_model=ExplainResponse,
    tags=["explain"],
    summary="解释一段 IPv4 地址空间由哪条规则或默认动作最终裁决",
)
def explain(request: ExplainRequest) -> dict:
    """在 ``query`` 范围内按“首条匹配规则生效”语义归因。

    query 中的每个地址归属于首条命中它的规则；未命中任何规则的部分
    归于 ``default_action``。归因项按规则索引升序、默认项最后返回，
    所有项不重不漏地覆盖整个 query；每项给出无损压缩后的最少 CIDR。
    基于区间归并计算，不逐地址枚举。
    """
    try:
        return explain_query(
            [(r.action, r.cidr) for r in request.rules],
            request.default_action,
            request.query,
        )
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/cidrs/hierarchy",
    response_model=HierarchyResponse,
    tags=["hierarchy"],
    summary="分析一组 IPv4 CIDR 的包含层级树及各网段独占地址",
)
def cidr_hierarchy(request: HierarchyRequest) -> dict:
    """为每个网段选择输入中**前缀最长的严格超网**作为唯一 parent，
    不存在则作为 root；兄弟/根节点按网络地址、前缀长度、输入顺序稳定排列。

    每个节点给出 ``total_addresses``，以及其范围扣除**全部直接子节点**
    地址并集后的 ``exclusive_address_count`` 与无损、数量最少的
    ``exclusive_cidrs``（复用现有区间差集与最少 CIDR 压缩）。

    条目数超出 1～500、非法 CIDR / IPv6、id 缺失或为空白均返回 **422**；
    id 重复或规范化后网络相同同样返回 **422**，并在 ``detail`` 中列出
    冲突的 id 与网络分组。
    """
    try:
        return build_cidr_hierarchy([(e.id, e.cidr) for e in request.entries])
    except DuplicateEntriesError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "存在重复的条目 id 或规范化后相同的网络",
                "duplicate_ids": exc.duplicate_ids,
                "duplicate_networks": exc.duplicate_networks,
            },
        ) from exc
