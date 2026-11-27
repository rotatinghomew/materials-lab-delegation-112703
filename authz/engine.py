"""代理授权核对引擎。

输入为只读资料（roles/grants/handover/transfers/timeline），引擎按时间
回放事件并维护委托与办理状态，同时支持在任意时刻做不落库的试算核对。

时间约定统一为半开区间：开始时刻含端点，结束时刻不含端点。调离时刻按
当班职责的结束处理；委托结束时刻以其原始 end 与上游变更时刻的较早者为准。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json

READ = "read"
HANDOVER = "handover"
SUBDELEGATE_READ = "subdelegate_read"

# 可再分派的仅限明确范围内的基本查阅；现场确认不在其列。
SUBDUTY_ALLOWED = {READ}

# 事件类型（timeline 中的中文 kind）
EVT_READ = "查阅"
EVT_FREEZE = "冻结代理"
EVT_REQUEST = "请求确认"
EVT_RESEND = "负责人重发"
EVT_TRANSFER = "调离"
EVT_ORIGIN = "移出确认"
EVT_DESTINATION = "接收确认"
EVT_CORRECTION = "交接修订"

# 决策原因码
PERSON_QUALIFICATION = "person_qualification"
GRANT_NOT_FOUND = "grant_not_found"
GRANT_OUTSIDE_WINDOW = "grant_outside_window"
GRANT_SITE_MISMATCH = "grant_site_mismatch"
GRANT_SUBJECT_MISMATCH = "grant_subject_mismatch"
GRANT_FROZEN = "grant_frozen"
GRANT_PARENT_INVALID = "grant_parent_invalid"
GRANT_PARENT_SCOPE = "grant_parent_scope"
GRANT_ISSUER_QUALIFICATION = "grant_issuer_qualification"
DUTY_NOT_IN_GRANT = "duty_not_in_grant"
SUBDUTY_NOT_PERMITTED = "subdelegation_not_permitted"
PRINCIPAL_MISMATCH = "principal_mismatch"
INDEPENDENCE_VIOLATION = "independence_violation"
TRANSFER_PART_MISMATCH = "transfer_part_mismatch"
TRANSFER_PRINCIPAL_MISMATCH = "transfer_principal_mismatch"
REVISION_MISMATCH = "revision_mismatch"
HANDOVER_NOT_PENDING = "handover_not_pending"
UNKNOWN_HANDOVER = "unknown_handover"
UNKNOWN_TRANSFER = "unknown_transfer"

_REASON_TEXT = {
    PERSON_QUALIFICATION: "使用人在该站此时刻没有有效在岗职责",
    GRANT_NOT_FOUND: "代理来源不存在",
    GRANT_OUTSIDE_WINDOW: "代理来源不在有效期间内",
    GRANT_SITE_MISMATCH: "代理来源与业务线站不一致",
    GRANT_SUBJECT_MISMATCH: "代理来源授予的使用人与登录人不一致",
    GRANT_FROZEN: "代理来源已被冻结或随上游冻结失效",
    GRANT_PARENT_INVALID: "再分派的上游来源已失效",
    GRANT_PARENT_SCOPE: "上游来源未授予相应范围的再分派许可",
    GRANT_ISSUER_QUALIFICATION: "委托人在授予时不具备该站在岗职责",
    DUTY_NOT_IN_GRANT: "该来源不支持本次业务动作",
    SUBDUTY_NOT_PERMITTED: "现场确认不得再分派",
    PRINCIPAL_MISMATCH: "该来源不足以覆盖交接所指向的责任人",
    INDEPENDENCE_VIOLATION: "同一人不得兼任当前交接的发起者与独立确认者",
    TRANSFER_PART_MISMATCH: "确认方与该移交单要求的线站一侧不符",
    TRANSFER_PRINCIPAL_MISMATCH: "该来源不足以覆盖本侧移交责任人",
    REVISION_MISMATCH: "交接内容已更正，须按最新修订重新确认",
    HANDOVER_NOT_PENDING: "交接已确认或已被阻塞，不能重复确认",
    UNKNOWN_HANDOVER: "交接单不存在",
    UNKNOWN_TRANSFER: "移交单不存在",
}


@dataclass
class Check:
    """单项核对结论。"""

    stage: str
    ok: bool
    reason: str = ""
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"stage": self.stage, "ok": self.ok, "reason": self.reason, "detail": self.detail}


@dataclass
class SourceVerdict:
    """代理源头与动作权限的核对结论。"""

    ok: bool
    reason: str = ""
    detail: str = ""
    root_principal: str | None = None
    chain: list[str] = field(default_factory=list)
    duties: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "detail": self.detail,
            "root_principal": self.root_principal,
            "chain": self.chain,
            "duties": self.duties,
        }


@dataclass
class Decision:
    """一次业务动作的完整决策。"""

    allowed: bool
    at: int
    action: str
    actor: str
    site: str
    grant: str
    checks: list[Check]
    source: SourceVerdict
    ref: str = ""
    reason: str = ""
    detail: str = ""
    event: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "at": self.at,
            "action": self.action,
            "actor": self.actor,
            "site": self.site,
            "grant": self.grant,
            "ref": self.ref,
            "reason": self.reason,
            "detail": self.detail,
            "checks": [c.to_dict() for c in self.checks],
            "source": self.source.to_dict(),
            "event": self.event,
        }


@dataclass
class _Ledger:
    """回放累积的内部状态。"""

    frozen: set[str] = field(default_factory=set)
    departures: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    # handover id -> 办理状态
    handovers: dict[str, dict[str, Any]] = field(default_factory=dict)
    # transfer id -> 移交状态
    transfers: dict[str, dict[str, Any]] = field(default_factory=dict)
    decisions: list[Decision] = field(default_factory=list)
    last_at: int = -1


class Engine:
    """以本地 JSON 资料装载的代理授权核对引擎。"""

    def __init__(self, data_dir: str | Path):
        root = Path(data_dir)
        self.roles: list[dict[str, Any]] = json.loads((root / "roles.json").read_text(encoding="utf-8"))
        self.grants: list[dict[str, Any]] = json.loads((root / "grants.json").read_text(encoding="utf-8"))
        self.handovers_raw: list[dict[str, Any]] = json.loads(
            (root / "handover.json").read_text(encoding="utf-8")
        )
        self.transfers_raw: list[dict[str, Any]] = json.loads(
            (root / "transfers.json").read_text(encoding="utf-8")
        )
        self.timeline: list[dict[str, Any]] = json.loads(
            (root / "timeline.json").read_text(encoding="utf-8")
        )

        self.grant_by_id: dict[str, dict[str, Any]] = {g["id"]: g for g in self.grants}
        self._children: dict[str, list[str]] = {}
        for g in self.grants:
            if g.get("parent"):
                self._children.setdefault(g["parent"], []).append(g["id"])
        # 各交接的初始办理状态
        self._initial_handovers = {
            h["id"]: {
                "id": h["id"],
                "site": h["site"],
                "opened_by": h["opened_by"],
                "principal": h["principal"],
                "grant": h["grant"],
                "record": h["record"],
                "state": "pending",
                "history": [],
            }
            for h in self.handovers_raw
        }
        # 各移交的初始状态（修订版本与两侧确认分开记录）
        self._initial_transfers = {
            t["id"]: {
                "id": t["id"],
                "origin": t["origin"],
                "destination": t["destination"],
                "from_principal": t["from_principal"],
                "to_principal": t["to_principal"],
                "revision": t["revision"],
                "item": t["item"],
                "confirmations": [],
                "revision_history": [],
            }
            for t in self.transfers_raw
        }
        self.max_at = max((e["at"] for e in self.timeline), default=0)

    # ------------------------------------------------------------------ 状态

    def _state_through(self, at: int) -> _Ledger:
        """重放到 at（含）为止的时间线，得到该时刻的办理状态。"""
        ledger = _Ledger(
            handovers={k: _clone(v) for k, v in self._initial_handovers.items()},
            transfers={k: _clone(v) for k, v in self._initial_transfers.items()},
        )
        for event in sorted(self.timeline, key=lambda e: e["at"]):
            if event["at"] > at:
                break
            self._apply(event, ledger, persist=True)
        ledger.last_at = at
        return ledger

    def _apply(self, event: dict[str, Any], ledger: _Ledger, persist: bool) -> Decision | None:
        kind = event["kind"]
        at = event["at"]
        facts = event.get("facts", {})
        if kind == EVT_FREEZE:
            decision = self._do_freeze(event["ref"], at, ledger, event)
        elif kind == EVT_TRANSFER:
            decision = self._do_departure(event["ref"], facts.get("site", ""), at, ledger, event)
        elif kind == EVT_RESEND:
            decision = self._do_resend(event["ref"], facts, at, ledger, event)
        elif kind == EVT_CORRECTION:
            decision = self._do_correction(event["ref"], facts, at, ledger, event)
        elif kind == EVT_READ:
            decision = self._decide(event["ref"], facts.get("site", ""), READ, facts["grant"], at,
                                    event=event, ledger=ledger)
        elif kind == EVT_REQUEST:
            decision = self._decide(facts["person"], "", HANDOVER, facts["grant"], at,
                                    handover_id=event["ref"], event=event, ledger=ledger)
        elif kind in (EVT_ORIGIN, EVT_DESTINATION):
            decision = self._decide(facts["actor"], "", HANDOVER, facts["grant"], at,
                                    transfer_id=event["ref"], side=kind,
                                    revision=facts.get("revision"), event=event, ledger=ledger)
        else:
            return None
        if persist and decision is not None:
            ledger.decisions.append(decision)
        return decision

    # ---------------------------------------------------------- 人员与委托

    def _role_active(self, person: str, site: str, at: int, ledger: _Ledger) -> bool:
        """本人资格：在该站此时刻是否有有效在岗职责（调离截断当班职责）。"""
        for r in self.roles:
            if r["subject"] != person or r["site"] != site:
                continue
            if not (r["starts"] <= at < r["ends"]):
                continue
            departed = False
            for d in ledger.departures.get(person, []):
                if d["site"] == site and d["at"] <= at:
                    departed = True
                    break
            if not departed:
                return True
        return False

    def _chain_of(self, grant_id: str) -> list[str]:
        """自使用的代理来源回溯到当班职责直接委托的完整委托链。"""
        chain: list[str] = []
        seen: set[str] = set()
        cur = grant_id
        while cur:
            if cur in seen or cur not in self.grant_by_id:
                break
            seen.add(cur)
            chain.append(cur)
            cur = self.grant_by_id[cur].get("parent", "")
        return chain

    def _subtree(self, grant_id: str) -> set[str]:
        out = {grant_id}
        for child in self._children.get(grant_id, []):
            out |= self._subtree(child)
        return out

    def check_source(self, actor: str, site: str, duty: str, grant_id: str, at: int,
                     ledger: _Ledger) -> SourceVerdict:
        """分别核对代理源头与本次动作权限，不触碰办理上下文规则。"""
        grant = self.grant_by_id.get(grant_id)
        if grant is None:
            return SourceVerdict(False, GRANT_NOT_FOUND, _REASON_TEXT[GRANT_NOT_FOUND])
        chain = self._chain_of(grant_id)
        duties = list(grant.get("duties", []))
        root = self.grant_by_id[chain[-1]] if chain else grant

        if grant["subject"] != actor:
            return SourceVerdict(False, GRANT_SUBJECT_MISMATCH,
                                 f"来源 {grant_id} 授予 {grant['subject']}，登录人为 {actor}",
                                 chain=chain, duties=duties)
        if grant["site"] != site:
            return SourceVerdict(False, GRANT_SITE_MISMATCH,
                                 f"来源站点 {grant['site']} 与业务站点 {site} 不一致",
                                 chain=chain, duties=duties)
        if not (grant["start"] <= at < grant["end"]):
            return SourceVerdict(False, GRANT_OUTSIDE_WINDOW,
                                 f"来源有效期 [{grant['start']}, {grant['end']}) 不含时刻 {at}",
                                 chain=chain, duties=duties)

        # 冻结沿委托链向下级联：上游被冻，下游再分派同步失效。
        frozen_link = next((gid for gid in chain if gid in ledger.frozen), None)
        if frozen_link is not None:
            return SourceVerdict(False, GRANT_FROZEN,
                                 f"委托链上的 {frozen_link} 已被冻结" +
                                 ("" if frozen_link == grant_id else f"，来源 {grant_id} 随之失效"),
                                 root_principal=root["issuer"], chain=chain, duties=duties)

        # 委托链上任何一段的授予人调离或当班职责结束，该来源即失效：
        # 源头直接委托失去职责基础，下游再分派失去合法上游。
        for gid in chain:
            node = self.grant_by_id[gid]
            if not self._role_active(node["issuer"], node["site"], at, ledger):
                reason = GRANT_ISSUER_QUALIFICATION if not node.get("parent") else GRANT_PARENT_INVALID
                return SourceVerdict(False, reason,
                                     f"委托人 {node['issuer']} 在 {node['site']} 站已无在岗职责，"
                                     f"来源 {grant_id} 失效",
                                     root_principal=root["issuer"], chain=chain, duties=duties)

        # 再分派来源：逐段检查上游的再分派许可与可再分派行为范围。
        if grant.get("parent"):
            for gid in chain:
                node = self.grant_by_id[gid]
                if not node.get("parent"):
                    continue
                parent = self.grant_by_id[node["parent"]]
                if SUBDELEGATE_READ not in parent.get("duties", []):
                    return SourceVerdict(False, GRANT_PARENT_SCOPE,
                                         f"上游来源 {parent['id']} 未授予再分派许可",
                                         root_principal=root["issuer"], chain=chain, duties=duties)
                if duty not in SUBDUTY_ALLOWED or duty not in node.get("duties", []):
                    return SourceVerdict(False, SUBDUTY_NOT_PERMITTED,
                                         "现场确认不能再分派，仅明确范围内的查阅可再分派",
                                         root_principal=root["issuer"], chain=chain, duties=duties)
            if duty not in duties:
                return SourceVerdict(False, DUTY_NOT_IN_GRANT,
                                     f"来源 {grant_id} 获准行为 {duties} 不含 {duty}",
                                     root_principal=root["issuer"], chain=chain, duties=duties)
        elif duty not in duties:
            return SourceVerdict(False, DUTY_NOT_IN_GRANT,
                                 f"来源 {grant_id} 获准行为 {duties} 不含 {duty}",
                                 root_principal=root["issuer"], chain=chain, duties=duties)

        return SourceVerdict(True, root_principal=root["issuer"], chain=chain, duties=duties)

    # ------------------------------------------------------------ 动作决策

    def _decide(self, actor: str, site: str, duty: str, grant_id: str, at: int,
                handover_id: str | None = None, transfer_id: str | None = None,
                side: str | None = None, revision: int | None = None,
                event: dict[str, Any] | None = None,
                ledger: _Ledger | None = None) -> Decision:
        """三段核对并落办理结果。ledger 为 None 时为不落库试算。"""
        own_ledger = ledger is None
        if own_ledger:
            ledger = self._state_through(at)

        ref = handover_id or transfer_id or ""
        checks: list[Check] = []

        # 侧别归一化：HTTP 层与试算可用英文别名，内部统一用中文事件名。
        if side == "origin":
            side = EVT_ORIGIN
        elif side == "destination":
            side = EVT_DESTINATION

        # 站点由办理上下文确定，避免调用方站点与单据站点不一致被忽略。
        context_site = site
        if handover_id is not None:
            hv = ledger.handovers.get(handover_id)
            if hv is not None:
                context_site = hv["site"]
        elif transfer_id is not None:
            tv = ledger.transfers.get(transfer_id)
            if tv is not None:
                context_site = tv["origin"] if side == EVT_ORIGIN else tv["destination"]
        # 第一段：本人资格
        person_ok = self._role_active(actor, context_site, at, ledger)
        checks.append(Check(
            "person", person_ok,
            "" if person_ok else PERSON_QUALIFICATION,
            f"{actor} 在 {context_site} 站的在岗职责核对"
            + ("通过" if person_ok else "不通过"),
        ))

        # 第二段：代理源头与动作权限
        source = self.check_source(actor, context_site, duty, grant_id, at, ledger)
        checks.append(Check(
            "source", source.ok,
            source.reason,
            f"来源 {grant_id} 的委托链与 {duty} 行为核对"
            + ("通过" if source.ok else "不通过"),
        ))

        # 第三段：本次业务动作的上下文权限
        context_ok = True
        context_reason = ""
        context_detail = ""
        if source.ok:
            if handover_id is not None:
                context_ok, context_reason, context_detail = self._check_handover_context(
                    handover_id, actor, source, at, ledger)
            elif transfer_id is not None:
                context_ok, context_reason, context_detail = self._check_transfer_context(
                    transfer_id, side, actor, revision, source, at, ledger)
        checks.append(Check(
            "action", context_ok, context_reason,
            self._action_label(duty, handover_id, transfer_id, side)
            + ("通过" if context_ok else "不通过"),
        ))

        allowed = person_ok and source.ok and context_ok
        reason, detail = self._first_failure(checks, source)
        decision = Decision(
            allowed=allowed, at=at, action=duty, actor=actor, site=context_site,
            grant=grant_id, checks=checks, source=source, ref=ref,
            reason=reason, detail=detail, event=event,
        )

        if not own_ledger:
            self._record(decision, ledger, handover_id, transfer_id, side, revision)
        return decision

    def _check_handover_context(self, handover_id: str, actor: str, source: SourceVerdict,
                                at: int, ledger: _Ledger) -> tuple[bool, str, str]:
        hv = ledger.handovers.get(handover_id)
        if hv is None:
            return False, UNKNOWN_HANDOVER, f"交接单 {handover_id} 不存在"
        # 一次交接确认必须由一个足以覆盖该操作的有效来源独立完成，
        # 不能把两条权利各取一部分拼起来替责任人签字。
        if source.root_principal != hv["principal"]:
            return False, PRINCIPAL_MISMATCH, (
                f"交接 {handover_id} 的责任人是 {hv['principal']}，"
                f"来源 {source.chain[0]} 仅覆盖 {source.root_principal}")
        # 同一人在不同身份下不能兼作当前交接的发起者与独立确认者。
        if actor == hv["opened_by"]:
            return False, INDEPENDENCE_VIOLATION, (
                f"{actor} 是交接 {handover_id} 的发起者，不能再做独立确认")
        if hv["state"] != "pending":
            return False, HANDOVER_NOT_PENDING, f"交接单 {handover_id} 当前状态为 {hv['state']}"
        return True, "", ""

    def _check_transfer_context(self, transfer_id: str, side: str | None, actor: str,
                                revision: int | None, source: SourceVerdict, at: int,
                                ledger: _Ledger) -> tuple[bool, str, str]:
        tv = ledger.transfers.get(transfer_id)
        if tv is None:
            return False, UNKNOWN_TRANSFER, f"移交单 {transfer_id} 不存在"
        if side == EVT_ORIGIN:
            want_site, want_principal = tv["origin"], tv["from_principal"]
        else:
            want_site, want_principal = tv["destination"], tv["to_principal"]
        grant = self.grant_by_id[source.chain[0]]
        if grant["site"] != want_site:
            return False, TRANSFER_PART_MISMATCH, (
                f"该确认属于 {want_site} 站一侧，来源站点为 {grant['site']}")
        if source.root_principal != want_principal:
            return False, TRANSFER_PRINCIPAL_MISMATCH, (
                f"本侧责任人是 {want_principal}，来源仅覆盖 {source.root_principal}")
        if revision is not None and revision != tv["revision"]:
            return False, REVISION_MISMATCH, (
                f"当前修订为 {tv['revision']}，确认引用的是修订 {revision}")
        if side == EVT_DESTINATION:
            # 两端人员都到齐也可能是同一人在两个站的有效代理下操作：
            # 接收确认人不得与已登记的移出确认人相同，接收站须另找有权人员。
            origin_actors = {c["actor"] for c in tv["confirmations"]
                             if c["side"] == EVT_ORIGIN and c["revision"] == tv["revision"]}
            if actor in origin_actors:
                return False, INDEPENDENCE_VIOLATION, (
                    f"{actor} 已完成移出确认，接收站须另找有权人员独立确认")
        return True, "", ""

    def _record(self, decision: Decision, ledger: _Ledger, handover_id: str | None,
                transfer_id: str | None, side: str | None, revision: int | None) -> None:
        if handover_id is not None and handover_id in ledger.handovers:
            hv = ledger.handovers[handover_id]
            entry = {"at": decision.at, "actor": decision.actor, "grant": decision.grant,
                     "allowed": decision.allowed, "reason": decision.reason}
            hv["history"].append(entry)
            if decision.allowed:
                hv["state"] = "confirmed"
                hv["confirmed_by"] = decision.actor
                hv["confirmed_grant"] = decision.grant
                hv["confirmed_at"] = decision.at
            # 被拒不改变状态，责任人可重新分发。
        if transfer_id is not None and transfer_id in ledger.transfers:
            tv = ledger.transfers[transfer_id]
            tv["confirmations"].append({
                "at": decision.at, "side": side, "actor": decision.actor,
                "grant": decision.grant, "revision": revision if revision is not None else tv["revision"],
                "allowed": decision.allowed, "reason": decision.reason,
            })

    # ------------------------------------------------------- 冻结/调离/重发

    def _do_freeze(self, grant_id: str, at: int, ledger: _Ledger,
                   event: dict[str, Any]) -> Decision:
        """带班组冻结：级联作废下游代理，重新核对未完成办理；已有其他合法
        来源的查阅不用中断。"""
        subtree = self._subtree(grant_id)
        ledger.frozen |= subtree
        blocked: list[str] = []
        for hid, hv in ledger.handovers.items():
            if hv["state"] == "pending" and (
                hv["grant"] in subtree
                or any(h["grant"] in subtree for h in hv["history"])
            ):
                hv["state"] = "blocked"
                hv["blocked_reason"] = GRANT_FROZEN
                hv["blocked_at"] = at
                blocked.append(hid)
        decision = Decision(
            allowed=True, at=at, action="freeze", actor="", site="", grant=grant_id,
            checks=[Check("freeze", True, detail=f"冻结 {grant_id} 及其下游 {sorted(subtree)}")],
            source=SourceVerdict(True, chain=self._chain_of(grant_id)),
            ref=grant_id, event=event,
            detail=f"级联失效 {sorted(subtree)}；待重核交接 {blocked or '无'}",
        )
        return decision

    def _do_departure(self, person: str, site: str, at: int, ledger: _Ledger,
                      event: dict[str, Any]) -> Decision:
        """调离信息由排班部门提供：当班职责结束，该人员授予的委托同步失效，
        指向其责任关系的待签交接不得自动改挂到另一条代理关系下。"""
        ledger.departures.setdefault(person, []).append({"site": site, "at": at})
        affected_grants = sorted(
            g["id"] for g in self.grants
            if g["issuer"] == person and g["site"] == site and g["start"] <= at < g["end"]
        )
        blocked: list[str] = []
        for hid, hv in ledger.handovers.items():
            if hv["state"] == "pending" and hv["principal"] == person and hv["site"] == site:
                hv["state"] = "blocked"
                hv["blocked_reason"] = PERSON_QUALIFICATION
                hv["blocked_at"] = at
                blocked.append(hid)
        decision = Decision(
            allowed=True, at=at, action="departure", actor=person, site=site, grant="",
            checks=[Check("person", True, detail=f"{person} 调离 {site} 站")],
            source=SourceVerdict(True), ref=person, event=event,
            detail=f"失效委托 {affected_grants or '无'}；待重新分发交接 {blocked or '无'}",
        )
        return decision

    def _do_resend(self, handover_id: str, facts: dict[str, Any], at: int,
                   ledger: _Ledger, event: dict[str, Any]) -> Decision:
        """负责人重发是明确的新交接选择，不是撤销结果的副本。"""
        hv = ledger.handovers.get(handover_id)
        person = facts["person"]
        grant_id = facts["grant"]
        if hv is None:
            return Decision(
                allowed=False, at=at, action="resend", actor=person, site="", grant=grant_id,
                checks=[Check("action", False, UNKNOWN_HANDOVER, "重发目标不存在")],
                source=SourceVerdict(False, UNKNOWN_HANDOVER), ref=handover_id,
                reason=UNKNOWN_HANDOVER, detail="", event=event)
        # 重发是责任人本人履行职责的重新分发：核对重发人在岗资格，以及所
        # 指向的代理来源对其使用人仍然有效、且源头责任就是重发人本人。
        person_ok = self._role_active(person, hv["site"], at, ledger)
        target = self.grant_by_id.get(grant_id)
        source = (
            self.check_source(target["subject"], hv["site"], HANDOVER, grant_id, at, ledger)
            if target is not None else SourceVerdict(False, GRANT_NOT_FOUND, "代理来源不存在")
        )
        scope_ok = source.ok and source.root_principal == person
        checks = [
            Check("person", person_ok,
                  "" if person_ok else PERSON_QUALIFICATION,
                  f"重发人 {person} 在 {hv['site']} 站的在岗职责核对"),
            Check("source", source.ok, source.reason,
                  f"重新分发所指向来源 {grant_id}（使用人 {target and target['subject']}）核对"),
            Check("action", scope_ok,
                  "" if scope_ok else PRINCIPAL_MISMATCH,
                  f"来源源头责任人须为重发人 {person}"),
        ]
        allowed = person_ok and source.ok and scope_ok
        if allowed:
            # 重发把责任关系明确改到重发来源所覆盖的责任人，旧选择留痕。
            hv["history"].append({
                "at": at, "kind": EVT_RESEND, "by": person, "grant": grant_id,
                "old_principal": hv["principal"], "new_principal": source.root_principal,
            })
            hv["principal"] = source.root_principal
            hv["grant"] = grant_id
            hv["opened_by"] = person
            hv["state"] = "pending"
            hv.pop("blocked_reason", None)
            hv.pop("blocked_at", None)
        reason = ""
        if not person_ok:
            reason = PERSON_QUALIFICATION
        elif not source.ok:
            reason = source.reason
        elif not scope_ok:
            reason = PRINCIPAL_MISMATCH
        return Decision(
            allowed=allowed, at=at, action="resend", actor=person, site=hv["site"],
            grant=grant_id, checks=checks, source=source, ref=handover_id,
            reason=reason, event=event,
            detail="" if allowed else "重发未生效，原办理状态保留",
        )

    def _do_correction(self, transfer_id: str, facts: dict[str, Any], at: int,
                       ledger: _Ledger, event: dict[str, Any]) -> Decision:
        """交接内容更正后两站都要重新确认，旧确认留给值班员追查。"""
        tv = ledger.transfers.get(transfer_id)
        if tv is None:
            return Decision(
                allowed=False, at=at, action="correction", actor="", site="", grant="",
                checks=[Check("action", False, UNKNOWN_TRANSFER, "移交单不存在")],
                source=SourceVerdict(False, UNKNOWN_TRANSFER), ref=transfer_id,
                reason=UNKNOWN_TRANSFER, event=event)
        old_revision = tv["revision"]
        new_revision = facts.get("revision", old_revision + 1)
        tv["revision_history"].append({
            "at": at, "old": old_revision, "new": new_revision,
            "item": facts.get("item", tv["item"]),
        })
        tv["revision"] = new_revision
        if "item" in facts:
            tv["item"] = facts["item"]
        return Decision(
            allowed=True, at=at, action="correction", actor="", site="", grant="",
            checks=[Check("action", True, detail=f"修订 {old_revision} -> {new_revision}")],
            source=SourceVerdict(True), ref=transfer_id, event=event,
            detail="旧确认保留留痕，两站须按新修订重新确认",
        )

    # ------------------------------------------------------------- 对外试算

    def evaluate_action(self, actor: str, site: str, duty: str, grant_id: str, at: int,
                        handover_id: str | None = None, transfer_id: str | None = None,
                        side: str | None = None, revision: int | None = None) -> dict[str, Any]:
        """以登录人自己的身份在指定时刻试算一次业务动作，不改变办理状态。"""
        decision = self._decide(actor, site, duty, grant_id, at,
                                handover_id=handover_id, transfer_id=transfer_id,
                                side=side, revision=revision)
        return decision.to_dict()

    def replay(self) -> list[dict[str, Any]]:
        """回放完整时间线，返回每个业务事件的逐段核对决策。"""
        ledger = _Ledger(
            handovers={k: _clone(v) for k, v in self._initial_handovers.items()},
            transfers={k: _clone(v) for k, v in self._initial_transfers.items()},
        )
        out: list[dict[str, Any]] = []
        for event in sorted(self.timeline, key=lambda e: e["at"]):
            decision = self._apply(event, ledger, persist=True)
            if decision is not None:
                out.append(decision.to_dict())
        return out

    def decisions_through(self, at: int) -> list[dict[str, Any]]:
        return [d.to_dict() for d in self._state_through(at).decisions]

    # --------------------------------------------------------------- 查询

    def effective_grants(self, person: str, site: str, at: int) -> list[dict[str, Any]]:
        """某人在某站某时刻仍可使用的代班权限（按来源分别列出，不做权利拼接）。"""
        ledger = self._state_through(at)
        out: list[dict[str, Any]] = []
        for g in sorted(self.grants, key=lambda x: x["id"]):
            if g["subject"] != person or g["site"] != site:
                continue
            verdict = self.check_source(person, site, READ, g["id"], at, ledger)
            if not verdict.ok:
                # read 不在行为内时，按 handover 再核对一次，避免漏掉纯交接来源。
                verdict = self.check_source(person, site, HANDOVER, g["id"], at, ledger)
            if verdict.ok:
                out.append({
                    "grant": g["id"],
                    "site": site,
                    "duties": verdict.duties,
                    "root_principal": verdict.root_principal,
                    "chain": verdict.chain,
                    "start": g["start"],
                    "end": g["end"],
                })
        return out

    def survivors_after_revocation(self, grant_id: str, at: int | None = None) -> dict[str, Any]:
        """某条委托收回（冻结）后，各站仍可使用的代班权限。

        at 缺省时取资料中该委托的冻结时刻；若资料没有对应冻结事件，则在
        时间线末尾做假设性收回分析，不改变任何回放结果。
        """
        if at is None:
            freeze_at = next((e["at"] for e in self.timeline
                              if e["kind"] == EVT_FREEZE and e["ref"] == grant_id), None)
            at = self.max_at if freeze_at is None else freeze_at
        ledger = self._state_through(at)
        hypothetical = grant_id not in ledger.frozen
        if hypothetical:
            ledger.frozen |= self._subtree(grant_id)
        invalidated = sorted(self._subtree(grant_id))
        by_site: dict[str, list[dict[str, Any]]] = {}
        for g in sorted(self.grants, key=lambda x: x["id"]):
            if g["id"] in self._subtree(grant_id):
                continue
            verdict = self.check_source(g["subject"], g["site"], READ, g["id"], at, ledger)
            if not verdict.ok:
                verdict = self.check_source(g["subject"], g["site"], HANDOVER, g["id"], at, ledger)
            if verdict.ok:
                by_site.setdefault(g["site"], []).append({
                    "grant": g["id"],
                    "subject": g["subject"],
                    "duties": verdict.duties,
                    "root_principal": verdict.root_principal,
                    "chain": verdict.chain,
                })
        return {
            "revoked": grant_id,
            "at": at,
            "invalidated": invalidated,
            "survivors": by_site,
        }

    def missing_confirmations(self, at: int) -> list[dict[str, Any]]:
        """站务人员签字前可查：还缺谁的确认。"""
        ledger = self._state_through(at)
        out: list[dict[str, Any]] = []
        for hid in sorted(ledger.handovers):
            hv = ledger.handovers[hid]
            if hv["state"] == "confirmed":
                continue
            missing = {
                "kind": "handover",
                "id": hid,
                "site": hv["site"],
                "state": hv["state"],
                "principal": hv["principal"],
                "record": hv["record"],
                "missing": [f"责任人 {hv['principal']} 一侧的独立确认"],
            }
            if hv["state"] == "blocked":
                missing["reason"] = hv.get("blocked_reason", "")
                missing["detail"] = "责任关系已变，需负责人重新分发后才能确认"
            out.append(missing)
        for tid in sorted(ledger.transfers):
            tv = ledger.transfers[tid]
            rev = tv["revision"]
            origin = [c for c in tv["confirmations"]
                      if c["side"] == EVT_ORIGIN and c["revision"] == rev and c["allowed"]]
            dest = [c for c in tv["confirmations"]
                    if c["side"] == EVT_DESTINATION and c["revision"] == rev and c["allowed"]]
            missing: list[str] = []
            if not origin:
                missing.append(f"移出站 {tv['origin']}（责任人 {tv['from_principal']}）的移出确认")
            if not dest:
                missing.append(f"接收站 {tv['destination']}（责任人 {tv['to_principal']}）的接收确认")
            if missing:
                out.append({
                    "kind": "transfer",
                    "id": tid,
                    "site": tv["origin"],
                    "state": "awaiting",
                    "revision": rev,
                    "item": tv["item"],
                    "missing": missing,
                })
        return out

    def receivable_transfers(self, site: str, at: int) -> list[dict[str, Any]]:
        """收物台核对真正可接收的移交：双方就同一份（同一修订）交接内容
        各自独立确认完成后才可登记接收。"""
        ledger = self._state_through(at)
        out: list[dict[str, Any]] = []
        for tid in sorted(ledger.transfers):
            tv = ledger.transfers[tid]
            if tv["destination"] != site:
                continue
            rev = tv["revision"]
            origin = [c for c in tv["confirmations"]
                      if c["side"] == EVT_ORIGIN and c["revision"] == rev and c["allowed"]]
            dest = [c for c in tv["confirmations"]
                    if c["side"] == EVT_DESTINATION and c["revision"] == rev and c["allowed"]]
            independent = bool(origin and dest
                               and {c["actor"] for c in origin}.isdisjoint(
                                   {c["actor"] for c in dest}))
            out.append({
                "id": tid,
                "item": tv["item"],
                "origin": tv["origin"],
                "destination": tv["destination"],
                "revision": rev,
                "receivable": independent,
                "origin_confirmations": origin,
                "destination_confirmations": dest,
                "reason": "" if independent else "双方尚未就同一修订各自独立确认",
            })
        return out

    def handover_status(self, handover_id: str, at: int) -> dict[str, Any]:
        hv = self._state_through(at).handovers.get(handover_id)
        if hv is None:
            raise KeyError(handover_id)
        return _clone(hv)

    def transfer_status(self, transfer_id: str, at: int) -> dict[str, Any]:
        tv = self._state_through(at).transfers.get(transfer_id)
        if tv is None:
            raise KeyError(transfer_id)
        return _clone(tv)

    # ----------------------------------------------------------------- 辅助

    @staticmethod
    def _action_label(duty: str, handover_id: str | None, transfer_id: str | None,
                      side: str | None) -> str:
        if handover_id is not None:
            return f"交接 {handover_id} 确认的上下文权限核对"
        if transfer_id is not None:
            return f"移交 {transfer_id} {side or ''} 的上下文权限核对"
        return f"{duty} 行为的上下文权限核对"

    @staticmethod
    def _first_failure(checks: list[Check], source: SourceVerdict) -> tuple[str, str]:
        for c in checks:
            if not c.ok:
                return c.reason, _REASON_TEXT.get(c.reason, c.detail) or c.detail
        return "", ""


def _clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))
