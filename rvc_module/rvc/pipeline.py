"""Оркестратор: вход (JSON сканеров) -> оценка по позициям -> обогащение -> отчёт.

Отчёт версии 2 содержит для КАЖДОЙ атаки оценку по трём позициям атакующего
(снаружи / изнутри-пользователь / изнутри-админ), в каждой — численную модель с
полной разбивкой параметров (для смежной программы) и качественную оценку словом
с цветом и обоснованием (для преподавателя), плюс методички атаки и защиты.
"""

from __future__ import annotations

import json
import os

from . import __version__
from .enrichment import build_references, build_target_software
from .knowledge import Knowledge
from .loaders import load_context
from .methodics import Methodics
from .models import ScanContext
from .positions import POSITION_META, POSITIONS
from .scoring import (VERDICT_NOT, VERDICT_PARTIALLY, VERDICT_REALIZABLE,
                      assess_all_positions, scoring_model_doc)

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


_BASIS_LABEL = {
    "product": "методичка под конкретный продукт",
    "type": "обобщённая методичка по типу атаки (уточните под ваш сервис)",
    "generic": "общий порядок исследования (тип атаки не распознан)",
}


def _build_finding(av, ctx: ScanContext, kb: Knowledge, methodics: Methodics) -> dict:
    assessments = assess_all_positions(av, ctx, kb, methodics)
    res = methodics.resolve(av)
    return {
        "attack_name": av.name,
        "attack_vector_id": av.id,
        "attack_type": av.attack_type,
        "port": av.target_port,
        "service": av.target_service,
        "family": methodics.specific_family_key(av),   # продукто-специфичное семейство или null
        "family_title": res["title"],
        "methodic_basis": res["basis"],                # product | type | generic
        "methodic_basis_label": _BASIS_LABEL.get(res["basis"], ""),
        "target_software": build_target_software(av, ctx, kb),
        "references": build_references(av, kb),
        "assessments": assessments,
        "methodic": res["attack_methodic"],
        "defense": res["defense_methodic"],
    }


def _finding_sort_key(f: dict):
    ext = f["assessments"]["external"]["numeric"]["score"]
    adm = f["assessments"]["internal_admin"]["numeric"]["score"]
    sev = max((_SEV_ORDER.get(a["severity"], 0) for a in f["assessments"].values()), default=0)
    return (-sev, -max(ext, adm), -ext)


def _counts_by_position(findings: list[dict]) -> dict:
    counts = {p: {VERDICT_REALIZABLE: 0, VERDICT_PARTIALLY: 0, VERDICT_NOT: 0} for p in POSITIONS}
    for f in findings:
        for p in POSITIONS:
            verdict = f["assessments"][p]["numeric"]["verdict"]
            counts[p][verdict] += 1
    return counts


def _positions_doc() -> list[dict]:
    out = []
    for p in POSITIONS:
        meta = POSITION_META[p]
        out.append({
            "id": p,
            "label": meta["label"],
            "group": meta["group"],
            "privilege": meta["privilege"],
            "has_lan": meta["has_lan"],
            "perimeter_controls_apply": meta["perimeter"],
            "description": meta["description"],
        })
    return out


def build_report(base_dir: str, kb: Knowledge | None = None,
                 methodics: Methodics | None = None) -> dict:
    """Полный отчёт по стенду в каталоге base_dir (контракт data/+history/ или tools/)."""
    kb = kb or Knowledge()
    methodics = methodics or Methodics()
    ctx = load_context(base_dir)

    findings = [_build_finding(av, ctx, kb, methodics) for av in ctx.attack_vectors]
    findings.sort(key=_finding_sort_key)

    counts = _counts_by_position(findings)

    return {
        "meta": {
            "rvc_version": __version__,
            "report_schema": 2,
            "generated_with_llm": False,
            "target": {
                "ip": ctx.target_ip,
                "hostname": ctx.server.hostname,
                "os": f"{ctx.server.os_name} {ctx.server.os_version}".strip(),
            },
            "host_inventory": "synthesized_from_ports" if ctx.server.synthesized else "from_scan_history",
            "host_inventory_note": (
                "Отдельной инвентаризации хоста во входных данных нет: достижимость и сервисы "
                "выведены из наблюдаемых открытых портов. Версии ПО/средства защиты считаются "
                "неизвестными (а не отсутствующими), что отражено мягким потолком оценки."
                if ctx.server.synthesized else
                "Использована инвентаризация хоста из scan_history."
            ),
            "reachable_ports": sorted(ctx.reachable_ports()),
            "mitre_snapshot": kb.snapshot,
            "mitre_sources": kb.sources,
            "methodics_snapshot": methodics.snapshot,
            "disclaimer": methodics.disclaimer,
            "positions": _positions_doc(),
            "scoring_model": scoring_model_doc(),
            "counts": {
                "attack_vectors": len(findings),
                "by_position": counts,
            },
        },
        "findings": findings,
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="RVC — отбор реализуемых уязвимостей (v2, по позициям)")
    parser.add_argument("--base", default=os.path.join(os.path.dirname(os.path.dirname(__file__)), "tools"),
                        help="каталог со сканами (tools/ или стенд с data/+history/)")
    parser.add_argument("--out", default="report.json", help="файл для записи отчёта")
    args = parser.parse_args()

    report = build_report(args.base)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    c = report["meta"]["counts"]["by_position"]
    print(f"Векторов: {report['meta']['counts']['attack_vectors']}")
    for p in POSITIONS:
        cc = c[p]
        print(f"  {POSITION_META[p]['label']:38} "
              f"реализуемо={cc['realizable']:2} возможно={cc['partially']:2} не реализуемо={cc['not_realizable']:2}")
    print(f"Отчёт записан: {args.out}")


if __name__ == "__main__":
    main()
