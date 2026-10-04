"""
数据模型
"""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# 任务的状态
class TaskState(str, Enum):
    PENDING = "PENDING" # 挂起
    PLANNING = "PLANNING" # 规划中
    EXECUTING = "EXECUTING" # 执行中
    REVIEWING = "REVIEWING" # 审查复合中
    SUCCESS = "SUCCESS" # 成功
    FAILED = "FAILED" # 失败
    CANCELLED = "CANCELLED" # 撤销


# 缺陷的严重级别：依次递减
class Severity(str, Enum): 
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

# 系统组件类型，用于追踪组件行为而非品牌。
class ComponentKind(str, Enum):
    LLM_AGENT = "llm-agent" # 大模型智能体
    TOOL_SCANNER = "tool-scanner" # 静态/工具扫描器
    GATE = "gate" # 校验门禁


# PR DIFF中的具体修改
@dataclass
class ChangedLine:
    path: str # 路径
    line: int # 行号
    content: str # 行内容


# 审查问题实体
@dataclass
class Finding:
    rule_id: str # 这条问题属于哪类规则
    severity: Severity # 问题严重程度
    title: str # 问题的摘要，一句话概括
    explanation: str # 为什么是这个问题
    path: str # 问题所在的文件路径
    line: int # 问题所在行号
    evidence: str # 能证明问题存在的代码片段原文
    fix: str # 建议怎么修改
    test: str # 建议加什么测试来验证修复
    confidence: float = 0.8 # LLM对这条问题的自信程度，默认为0.8
    evidence_refs: List[Dict[str, Any]] = field(default_factory=list) # 结构化的证据引用列表
    call_chain: List[Dict[str, Any]] = field(default_factory=list) # 函数调用链
    source: str = "unknown" # 这条问题是谁找出来的
    gate: Dict[str, Any] = field(default_factory=dict) # 这个问题已经通过了哪些门禁校验和对应结果
    # Canonical taxonomy used for evaluation.  rule_id remains an internal or
    # reviewer-specific label and is not required to be stable across models.
    cwe: Optional[str] = None # 跨模型评测用的标准漏洞分类，比如CWE

    def to_dict(self) -> Dict[str, Any]:
        """将finding对象转化为python字典返回"""
        value = asdict(self)
        value["severity"] = self.severity.value
        return value


# 整份审查报告
@dataclass
class ReviewReport:
    repository: str # 被审查的仓库名字
    pull_request: Optional[int] # PR编号
    summary: str # lead写的总结
    risk: str # 真个PR的风险等级（粗粒度），上面的finding的severity是细粒度的
    findings: List[Finding] = field(default_factory=list) # 对应的所有finding列表
    files_reviewed: List[str] = field(default_factory=list) # 审查覆盖的文件路径
    reviewer: str = "local-rules" # 谁来执行审查
    collaboration: Dict[str, Any] = field(default_factory=dict) # 多agent协作过程的快照，比如Lead叫了哪些worker，critic挑战了几条
    run_mode: Dict[str, Any] = field(default_factory=dict) # 运行配置快照，比如启动了哪些agent和skill
    components: List[Dict[str, Any]] = field(default_factory=list) # 本次任务用到了哪些组建：哪个LLM？哪些门禁？哪些扫描器？
    execution: Dict[str, Any] = field(default_factory=dict) # 本次任务的执行统计：总步数、token消耗、总费用等

    def to_dict(self) -> Dict[str, Any]:
        """转化为python字典返回"""
        return {
            "repository": self.repository,
            "pull_request": self.pull_request,
            "summary": self.summary,
            "risk": self.risk,
            "findings": [item.to_dict() for item in self.findings],
            "files_reviewed": self.files_reviewed,
            "reviewer": self.reviewer,
            "collaboration": self.collaboration,
            "run_mode": self.run_mode,
            "components": self.components,
            "execution": self.execution,
        }


# 执行轨迹点
@dataclass
class TraceEvent:
    step: int # 当前是第几步，用于checkpoint
    state: TaskState # 当前任务状态
    message: str # 轨迹点的文字描述，相当于一份摘要
    created_at: str # 整个轨迹点产生的时间，是UTC ISO格式

    def to_dict(self) -> Dict[str, Any]:
        """转化为列表并返回"""
        value = asdict(self)
        value["state"] = self.state.value
        return value
