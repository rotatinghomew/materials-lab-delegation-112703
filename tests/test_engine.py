"""代理授权引擎的领域规则核对。

以 data/ 中的合成演练为基准，覆盖三段独立核对、再分派范围、冻结级联、
责任人覆盖与独立确认、跨站双方独立确认、调离与重新分发、修订重新确认。
"""
import unittest

from authz import Engine
from authz.engine import (
    EVT_CORRECTION,
    EVT_DESTINATION,
    EVT_ORIGIN,
    GRANT_FROZEN,
    GRANT_ISSUER_QUALIFICATION,
    GRANT_PARENT_SCOPE,
    GRANT_SITE_MISMATCH,
    GRANT_SUBJECT_MISMATCH,
    INDEPENDENCE_VIOLATION,
    PERSON_QUALIFICATION,
    PRINCIPAL_MISMATCH,
    REVISION_MISMATCH,
    SUBDUTY_NOT_PERMITTED,
)
from replay import ROOT

DATA = ROOT / "data"


class EngineTestBase(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(DATA)

    def decisions(self, through):
        return {d["event"]["at"]: d for d in self.engine.decisions_through(through)}


class TimelineDecisionTests(EngineTestBase):
    def test_subdelegated_read_allowed_within_chain(self):
        # t38：s9 经 g23（g21 的再分派）在 east 查阅，链条与范围都成立。
        d = self.decisions(38)[38]
        self.assertTrue(d["allowed"])
        self.assertEqual([c["stage"] for c in d["checks"]], ["person", "source", "action"])
        self.assertEqual(d["source"]["chain"], ["g23", "g21"])
        self.assertEqual(d["source"]["root_principal"], "s1")

    def test_transfer_origin_confirmation_allowed(self):
        d = self.decisions(35)[35]
        self.assertTrue(d["allowed"])
        self.assertEqual(d["ref"], "T11")
        self.assertEqual(d["source"]["root_principal"], "s1")

    def test_same_person_two_site_proxies_cannot_confirm_both_sides(self):
        # t39：s8 同时握有 east 的 g21 与 west 的 g26，两端都到齐也不能
        # 由同一人独立确认，接收站须另找有权人员。
        d = self.decisions(39)[39]
        self.assertFalse(d["allowed"])
        self.assertEqual(d["reason"], INDEPENDENCE_VIOLATION)
        # 被拒不登记为有效确认。
        tv = self.engine.transfer_status("T11", 39)
        self.assertEqual(len([c for c in tv["confirmations"] if c["allowed"]]), 1)

    def test_independent_destination_confirmation_marks_receivable(self):
        d = self.decisions(40)[40]
        self.assertTrue(d["allowed"])
        rows = self.engine.receivable_transfers("west", 40)
        t11 = next(r for r in rows if r["id"] == "T11")
        self.assertTrue(t11["receivable"])
        # T12 两侧确认都还没有，不可接收。
        t12 = next(r for r in rows if r["id"] == "T12")
        self.assertFalse(t12["receivable"])

    def test_freeze_cascades_and_keeps_other_lawful_read(self):
        # t41：冻结 g21，下游 g23 同步失效；H8 进入重新核对。
        d = self.decisions(41)[41]
        self.assertTrue(d["allowed"])
        self.assertIn("g23", d["detail"])
        hv = self.engine.handover_status("H8", 41)
        self.assertEqual(hv["state"], "blocked")
        # 冻结后 g21/g23 都不能再使用。
        self.assertFalse(self.engine.evaluate_action("s8", "east", "read", "g21", 42)["allowed"])
        self.assertFalse(self.engine.evaluate_action("s9", "east", "read", "g23", 42)["allowed"])
        # t45：s9 另有 g25 这条合法来源，查阅不中断。
        self.assertTrue(self.decisions(45)[45]["allowed"])

    def test_handover_requires_single_source_covering_principal(self):
        # t47：H8 责任人是 s1，g22 只覆盖 s2；不能把两条权利拼起来签字。
        d = self.decisions(47)[47]
        self.assertFalse(d["allowed"])
        self.assertEqual(d["reason"], PRINCIPAL_MISMATCH)
        self.assertEqual(self.engine.handover_status("H8", 47)["state"], "blocked")

    def test_initiator_cannot_be_independent_confirmer(self):
        # t53：H9 由 s8 发起，s8 不能再以任何身份独立确认自己的交接。
        d = self.decisions(53)[53]
        self.assertFalse(d["allowed"])
        self.assertEqual(d["reason"], INDEPENDENCE_VIOLATION)
        self.assertEqual(self.engine.handover_status("H9", 53)["state"], "pending")

    def test_principal_resend_is_explicit_new_choice_then_signable(self):
        # t56：s2 以 g22 重发 H8，责任关系明确改到 s2，旧选择留痕。
        resend = self.decisions(56)[56]
        self.assertTrue(resend["allowed"])
        hv = self.engine.handover_status("H8", 56)
        self.assertEqual(hv["principal"], "s2")
        self.assertEqual(hv["state"], "pending")
        self.assertEqual(hv["history"][-1]["old_principal"], "s1")
        # t62：重发后的同一份交接可由 s8 依 g22 独立确认。
        sign = self.decisions(62)[62]
        self.assertTrue(sign["allowed"])
        self.assertEqual(self.engine.handover_status("H8", 62)["state"], "confirmed")

    def test_departure_revokes_grants_and_blocks_remaining_handovers(self):
        # t67：s2 调离 east，其授予的 g22、g25 失效，待签交接不得自动改挂。
        d = self.decisions(67)[67]
        self.assertTrue(d["allowed"])
        for hid in ("H9", "H10"):
            hv = self.engine.handover_status(hid, 67)
            self.assertEqual(hv["state"], "blocked")
        # 已完成的 H8 确认结果保留，不回滚。
        self.assertEqual(self.engine.handover_status("H8", 67)["state"], "confirmed")
        # g22/g25 不能再使用；west 站的委托与 s2 无关，继续有效。
        self.assertFalse(self.engine.evaluate_action("s8", "east", "handover", "g22", 70)["allowed"])
        self.assertFalse(self.engine.evaluate_action("s9", "east", "read", "g25", 70)["allowed"])
        west = {g["grant"] for g in self.engine.effective_grants("s9", "west", 70)}
        self.assertEqual(west, {"g27", "g24"})


class ThreeStageSeparationTests(EngineTestBase):
    def test_person_qualification_fails_independently(self):
        # s4 在 west 的 lead 职责 150 结束；150 时刻已无本人资格。
        d = self.engine.evaluate_action("s4", "west", "handover", "g27", 150)
        self.assertFalse(d["allowed"])
        self.assertEqual(d["checks"][0]["reason"], PERSON_QUALIFICATION)

    def test_grant_subject_mismatch_is_source_failure(self):
        d = self.engine.evaluate_action("s9", "east", "read", "g21", 30)
        self.assertFalse(d["allowed"])
        self.assertEqual(d["checks"][1]["reason"], GRANT_SUBJECT_MISMATCH)

    def test_site_mismatch_is_source_failure(self):
        d = self.engine.evaluate_action("s8", "west", "read", "g21", 30)
        self.assertFalse(d["allowed"])
        self.assertEqual(d["checks"][1]["reason"], GRANT_SITE_MISMATCH)

    def test_window_half_open_end_exclusive(self):
        # g24 区间 [20,85)：84 有效，85 失效。
        self.assertTrue(self.engine.evaluate_action("s9", "west", "read", "g24", 84)["allowed"])
        d = self.engine.evaluate_action("s9", "west", "read", "g24", 85)
        self.assertFalse(d["allowed"])
        self.assertEqual(d["checks"][1]["reason"], "grant_outside_window")

    def test_duty_not_in_grant(self):
        # g24 只有 read，不能用于交接确认（站点与本人资格均满足，卡在行为）。
        d = self.engine.evaluate_action("s9", "west", "handover", "g24", 50)
        self.assertFalse(d["allowed"])
        self.assertEqual(d["checks"][1]["reason"], "duty_not_in_grant")

    def test_handover_confirm_uses_handover_duty_even_for_read_like_records(self):
        # H10 由 s4 发起、责任人是 s2；s8 以 g22 做独立确认应当通过。
        d = self.engine.evaluate_action("s8", "east", "handover", "g22", 30,
                                        handover_id="H10")
        self.assertTrue(d["allowed"])


class SubdelegationTests(EngineTestBase):
    def test_handover_cannot_be_subdelegated(self):
        # 再分派来源 g23 只含 read：现场确认不在可再分派范围内。
        d = self.engine.evaluate_action("s9", "east", "handover", "g23", 30)
        self.assertFalse(d["allowed"])
        self.assertEqual(d["checks"][1]["reason"], SUBDUTY_NOT_PERMITTED)

    def test_subdelegation_requires_parent_scope(self):
        # g22 没有 subdelegate_read；用一条假设挂在 g22 下的来源试算时，
        # 通过直接核查链条范围原因码验证（资料未造该来源，这里验证 g23 的
        # 正向链条对照：g21 有 subdelegate_read 才允许 g23）。
        ok = self.engine.evaluate_action("s9", "east", "read", "g23", 30)
        self.assertTrue(ok["allowed"])
        # g22 缺少再分派标记，若把 g23 的父级替换为 g22 则应拒绝。
        original = self.engine.grant_by_id["g23"]["parent"]
        try:
            self.engine.grant_by_id["g23"]["parent"] = "g22"
            self.engine.grant_by_id["g23"]["start"] = 30
            d = self.engine.evaluate_action("s9", "east", "read", "g23", 30)
            self.assertFalse(d["allowed"])
            self.assertEqual(d["checks"][1]["reason"], GRANT_PARENT_SCOPE)
        finally:
            self.engine.grant_by_id["g23"]["parent"] = original

    def test_frozen_parent_invalidates_child_source(self):
        d = self.engine.evaluate_action("s9", "east", "read", "g23", 42)
        self.assertFalse(d["allowed"])
        self.assertEqual(d["checks"][1]["reason"], GRANT_FROZEN)

    def test_departed_issuer_invalidates_downstream_chain(self):
        d = self.engine.evaluate_action("s9", "east", "read", "g25", 70)
        self.assertFalse(d["allowed"])
        self.assertEqual(d["checks"][1]["reason"], GRANT_ISSUER_QUALIFICATION)


class TransferRuleTests(EngineTestBase):
    def _with_correction(self, at: int, transfer_id: str, revision: int, item: str | None = None):
        """向时间线注入一份内容更正，返回带该事件的新引擎（不改原始资料）。"""
        engine = Engine(DATA)
        engine.timeline = sorted(
            engine.timeline + [{
                "at": at, "kind": EVT_CORRECTION, "ref": transfer_id,
                "facts": {"revision": revision, **({"item": item} if item else {})},
            }],
            key=lambda e: e["at"],
        )
        return engine

    def test_grant_from_wrong_side_rejected_for_confirmation(self):
        # g21 属 east 一侧，拿去做 T11 的 west 接收确认，站点一侧不符即拒。
        d = self.engine.evaluate_action("s8", "east", "handover", "g21", 36,
                                        transfer_id="T11", side="destination", revision=1)
        self.assertFalse(d["allowed"])
        self.assertEqual(d["checks"][1]["reason"], GRANT_SITE_MISMATCH)

    def test_revision_mismatch_requires_reconfirmation(self):
        engine = self._with_correction(42, "T11", 2, "仪表 A5（加封）")
        d = engine.evaluate_action("s9", "west", "handover", "g27", 43,
                                   transfer_id="T11", side="destination", revision=1)
        self.assertFalse(d["allowed"])
        self.assertEqual(d["reason"], REVISION_MISMATCH)

    def test_correction_voids_old_confirmations_but_keeps_audit_trail(self):
        # T12（责任人 s2 -> s4）先完成修订 1 的两侧独立确认，再更正内容。
        engine = Engine(DATA)
        engine.timeline = sorted(
            engine.timeline + [
                {"at": 36, "kind": EVT_ORIGIN, "ref": "T12",
                 "facts": {"actor": "s8", "grant": "g22", "revision": 1}},
                {"at": 37, "kind": EVT_DESTINATION, "ref": "T12",
                 "facts": {"actor": "s9", "grant": "g27", "revision": 1}},
                {"at": 42, "kind": EVT_CORRECTION, "ref": "T12",
                 "facts": {"revision": 2, "item": "仪表 A6（加封）"}},
            ],
            key=lambda e: e["at"],
        )
        tv = engine.transfer_status("T12", 42)
        self.assertEqual(tv["revision"], 2)
        # 旧确认仍在留痕里，但收物台按新修订判定不可接收。
        self.assertEqual(len(tv["confirmations"]), 2)
        rows = engine.receivable_transfers("west", 42)
        self.assertFalse(next(r for r in rows if r["id"] == "T12")["receivable"])
        missing = {m["id"]: m for m in engine.missing_confirmations(42)}
        self.assertIn("T12", missing)
        self.assertEqual(len(missing["T12"]["missing"]), 2)
        # 按新修订重新两侧独立确认后才可接收（经时间线注入，确认真实入册）。
        engine.timeline = sorted(
            engine.timeline + [
                {"at": 43, "kind": EVT_ORIGIN, "ref": "T12",
                 "facts": {"actor": "s8", "grant": "g22", "revision": 2}},
                {"at": 44, "kind": EVT_DESTINATION, "ref": "T12",
                 "facts": {"actor": "s9", "grant": "g27", "revision": 2}},
            ],
            key=lambda e: e["at"],
        )
        rows = engine.receivable_transfers("west", 44)
        self.assertTrue(next(r for r in rows if r["id"] == "T12")["receivable"])

    def test_one_sided_revocation_keeps_other_side_confirmation(self):
        # 冻结 g21（移出侧来源）发生在两侧确认之后：既有确认仍可供后续
        # 办理使用，只要内容与责任人未变；T11 依旧可接收。
        rows = self.engine.receivable_transfers("west", 42)
        self.assertTrue(next(r for r in rows if r["id"] == "T11")["receivable"])

    def test_dry_run_does_not_mutate_ledger(self):
        before = self.engine.transfer_status("T11", 34)
        self.engine.evaluate_action("s8", "west", "handover", "g26", 34,
                                    transfer_id="T11", side="destination", revision=1)
        after = self.engine.transfer_status("T11", 34)
        self.assertEqual(before["confirmations"], after["confirmations"])


class QueryTests(EngineTestBase):
    def test_effective_grants_listed_per_source(self):
        rows = self.engine.effective_grants("s8", "east", 30)
        ids = {r["grant"] for r in rows}
        self.assertEqual(ids, {"g21", "g22"})
        # 多条来源分别列出，不合并权利。
        g21 = next(r for r in rows if r["grant"] == "g21")
        self.assertEqual(g21["root_principal"], "s1")
        self.assertIn("handover", g21["duties"])

    def test_survivors_after_g21_revocation(self):
        report = self.engine.survivors_after_revocation("g21", 41)
        self.assertEqual(set(report["invalidated"]), {"g21", "g23"})
        east = {r["grant"] for r in report["survivors"].get("east", [])}
        west = {r["grant"] for r in report["survivors"].get("west", [])}
        # east 站 g22/g25 不受影响；west 站来源全部保留。
        self.assertEqual(east, {"g22", "g25"})
        self.assertEqual(west, {"g24", "g26", "g27"})

    def test_hypothetical_revocation_never_frozen_in_data(self):
        # g22 在资料中没有冻结事件：缺省在时间线末尾做假设性收回分析。
        report = self.engine.survivors_after_revocation("g22")
        self.assertEqual(report["invalidated"], ["g22"])
        east = {r["grant"] for r in report["survivors"].get("east", [])}
        # g22 已假设失效，且 s2 已调离使 g25 也失效，east 无幸存来源。
        self.assertEqual(east, set())
        # 假设分析不改变真实回放：g22 在调离前的试算仍按原规则判定。
        self.assertTrue(
            self.engine.evaluate_action("s8", "east", "read", "g22", 50)["allowed"])

    def test_missing_confirmations_before_signing(self):
        at40 = {m["id"]: m for m in self.engine.missing_confirmations(40)}
        self.assertIn("H8", at40)
        self.assertIn("H9", at40)
        t12 = at40["T12"]
        self.assertEqual(len(t12["missing"]), 2)
        # T11 两侧独立确认齐备，不再出现在缺确认清单。
        self.assertNotIn("T11", at40)

    def test_missing_confirmations_after_freeze_explains_block(self):
        rows = {m["id"]: m for m in self.engine.missing_confirmations(42)}
        self.assertEqual(rows["H8"]["state"], "blocked")
        self.assertTrue(rows["H8"]["detail"])

    def test_receivable_filter_by_site(self):
        east = self.engine.receivable_transfers("east", 40)
        self.assertEqual(east, [])
        west = {r["id"]: r for r in self.engine.receivable_transfers("west", 40)}
        self.assertEqual(set(west), {"T11", "T12"})

    def test_replay_covers_all_business_events(self):
        decisions = self.engine.replay()
        kinds = {(d["event"]["at"], d["event"]["kind"]) for d in decisions}
        # 冻结、调离、重发等管理事件也产生决策留痕。
        self.assertIn((41, "冻结代理"), kinds)
        self.assertIn((67, "调离"), kinds)
        self.assertIn((56, "负责人重发"), kinds)
        # 时间线共 11 个事件，全部产生决策留痕。
        self.assertEqual(len(decisions), len(self.engine.timeline))


class ReplayConsistencyTests(EngineTestBase):
    def test_repeated_state_build_is_deterministic(self):
        first = self.engine.decisions_through(67)
        second = self.engine.decisions_through(67)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
