"""FastAPI 应用：IPv4 CIDR 遮蔽分析与规则集等价性比较 API。"""
from __future__ import annotations

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

from .analyzer import (
    InvalidCIDRError,
    analyze_rules,
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
        "或通过 /explain 解释一段地址空间由哪条规则或默认动作最终裁决。"
    ),
    version="1.2.0",
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
