"""Оркестратор: вход (JSON) -> вердикты -> обогащение -> отчёт."""

from __future__ import annotations

import json
import os
from dataclasses import asdict

from . import __version__
from .engine import VERDICT_NOT, VERDICT_PARTIALLY, VERDICT_REALIZABLE, assess_vector
from .enrichment import build_playbook, build_references, build_target_software
from .knowledge import Knowledge
from .loaders import load_context
from .models import Finding, ScanContext

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
_VERDICT_ORDER = {VERDICT_REALIZABLE: 3, VERDICT_PARTIALLY: 2, VERDICT_NOT: 1}


def _build_finding(av, assessment: dict, ctx: ScanContext, kb: Knowledge) -> Finding:
    return Finding(
        attack_name=av.name,
        attack_vector_id=av.id,
        attack_type=av.attack_type,
        severity=assessment["severity"],
        port=av.target_port,
        service=av.target_service,
        verdict=assessment["verdict"],
        confidence=assessment["confidence"],
        reason=assessment["reason"],
        trace=assessment["trace"],
        references=build_references(av, kb),
        target_software=build_target_software(av, ctx, kb),
        playbook=build_playbook(av, ctx, kb),
        source="attacker",
    )


def _finding_to_dict(f: Finding) -> dict:
    data = asdict(f)
    data["trace"] = [asdict(c) for c in f.trace]
    return data


def _sort_key(f: Finding):
    return (-_VERDICT_ORDER.get(f.verdict, 0), -f.confidence, -_SEV_ORDER.get(f.severity, 0))


def _trivy_summary(ctx: ScanContext) -> dict:
    reachable = ctx.reachable_ports()
    reachable_services = " ".join(
        (ctx.external_ports[p].service + " " + ctx.external_ports[p].banner).lower()
        for p in reachable if p in ctx.external_ports
    )
    exposed = sum(1 for v in ctx.trivy if v.pkg_name and v.pkg_name.lower() in reachable_services)
    by_sev: dict[str, int] = {}
    for v in ctx.trivy:
        by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
    return {
        "total": len(ctx.trivy),
        "by_severity": by_sev,
        "exposed_on_reachable_service": exposed,
        "note": (
            "Уязвимости пакетов из манифестов кода (Trivy) не имеют сетевого пути снаружи: "
            "веб-/БД-сервис, отдающий эти зависимости, на стенде не публикуется. "
            "В реализуемые не включены."
        ),
    }


def build_report(base_dir: str, kb: Knowledge | None = None) -> dict:
    """Полный отчёт по стенду в каталоге base_dir."""
    kb = kb or Knowledge()
    ctx = load_context(base_dir)

    findings = [_build_finding(av, assess_vector(av, ctx, kb), ctx, kb) for av in ctx.attack_vectors]
    findings.sort(key=_sort_key)

    groups = {VERDICT_REALIZABLE: [], VERDICT_PARTIALLY: [], VERDICT_NOT: []}
    for f in findings:
        groups[f.verdict].append(_finding_to_dict(f))

    return {
        "meta": {
            "rvc_version": __version__,
            "target": {
                "ip": ctx.target_ip,
                "hostname": ctx.server.hostname,
                "os": f"{ctx.server.os_name} {ctx.server.os_version}".strip(),
            },
            "mitre_snapshot": kb.snapshot,
            "mitre_sources": kb.sources,
            "generated_with_llm": False,
            "reachable_ports": sorted(ctx.reachable_ports()),
            "counts": {
                "attack_vectors": len(ctx.attack_vectors),
                "realizable": len(groups[VERDICT_REALIZABLE]),
                "partially": len(groups[VERDICT_PARTIALLY]),
                "not_realizable": len(groups[VERDICT_NOT]),
            },
        },
        "realizable_vulnerabilities": groups[VERDICT_REALIZABLE],
        "partially_realizable": groups[VERDICT_PARTIALLY],
        "rejected": groups[VERDICT_NOT],
        "trivy_summary": _trivy_summary(ctx),
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="RVC — отбор реализуемых уязвимостей")
    parser.add_argument("--base", default=os.path.dirname(os.path.dirname(__file__)), help="каталог со стендом (data/, history/)")
    parser.add_argument("--out", default="report.json", help="файл для записи отчёта")
    args = parser.parse_args()

    report = build_report(args.base)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    c = report["meta"]["counts"]
    print(f"Реализуемо: {c['realizable']} | частично: {c['partially']} | отклонено: {c['not_realizable']}")
    print(f"Отчёт записан: {args.out}")


if __name__ == "__main__":
    main()
