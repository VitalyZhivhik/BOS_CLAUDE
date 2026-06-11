"""Прозрачная численная модель реализуемости + вывод качественной оценки.

Зачем модель именно такая:
  * Разработчику-смежнику нужна ЧИСЛЕННАЯ оценка с разбивкой по параметрам
    («за что повысил/понизил и на сколько») и порогами — это `numeric`.
  * Преподавателю нужна КАЧЕСТВЕННАЯ оценка словами с цветом
    (реализуемо/возможно/не реализуемо = зелёный/жёлтый/красный) и обоснованием —
    это `qualitative`, и она ДЕТЕРМИНИРОВАННО выводится из numeric (один источник
    истины -> согласованность и воспроизводимость).
  * Обе оценки считаются отдельно для каждой ПОЗИЦИИ атакующего (снаружи /
    изнутри-пользователь / изнутри-админ).

Устройство numeric (аддитивная модель, 0..100):
  итог = clamp( BASE + Σ factor.delta , 0, 100 ), затем применяются:
    soft_cap — «мягкий потолок» (например, версия/патч не подтверждены -> нельзя
               признать полностью реализуемой, ставим потолок жёлтой зоны);
    gates    — жёсткие отсечки (недостижимо / не тот продукт / нужна L2-позиция),
               форсирующие вердикт «не реализуемо» независимо от баллов.
Каждый фактор и каждый гейт несут человекочитаемую улику (evidence) — это и есть
содержимое всплывающего окна с расчётами и строки обоснования.
"""

from __future__ import annotations

from . import engine
from .knowledge import Knowledge
from .methodics import Methodics
from .models import AttackVector, ScanContext
from .positions import POSITION_META, POSITIONS, privilege_rank

# --- параметры модели (выносятся в отчёт -> самодокументируемость) ------------
BASE_SCORE = 50
GREEN_MIN = 65   # >= этого -> реализуемо (зелёный)
YELLOW_MIN = 35  # [YELLOW_MIN, GREEN_MIN) -> возможно (жёлтый); ниже -> не реализуемо (красный)
YELLOW_CAP = GREEN_MIN - 1  # мягкий потолок жёлтой зоны (64)

_MATURITY_DELTA = {"weaponized": 14, "poc": 7, "tooling": 4, "native": 2}
_MATURITY_LABEL = {
    "weaponized": "готовый боевой эксплойт (Metasploit/рабочий PoC)",
    "poc": "публичный proof-of-concept",
    "tooling": "стандартный инструментарий",
    "native": "штатные средства протокола/ОС",
}
_SEVERITY_DELTA = {"CRITICAL": 8, "HIGH": 5, "MEDIUM": 2, "LOW": 0, "UNKNOWN": 0}

VERDICT_REALIZABLE = "realizable"
VERDICT_PARTIALLY = "partially"
VERDICT_NOT = "not_realizable"

_BAND = {
    VERDICT_REALIZABLE: ("green", "реализуемо"),
    VERDICT_PARTIALLY: ("yellow", "возможно"),
    VERDICT_NOT: ("red", "не реализуемо"),
}


def _factor(key: str, label: str, delta: int, evidence: str, verify: str | None = None) -> dict:
    f = {"key": key, "label": label, "delta": delta, "evidence": evidence}
    if verify:
        f["verify"] = verify  # «что уточнить», чтобы подтвердить реализуемость
    return f


def _gate(key: str, evidence: str) -> dict:
    return {"key": key, "evidence": evidence}


def _clamp(v: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, v))


def _dedup(seq: list[str]) -> list[str]:
    return list(dict.fromkeys(s for s in seq if s))


# --------------------------------------------------------------------------- #
#  Отдельные факторы
# --------------------------------------------------------------------------- #

def _reachability(av: AttackVector, ctx: ScanContext, ex: dict, pos: dict):
    """Возвращает (factor|None, gate|None) по достижимости в данной позиции."""
    observed = ctx.reachable_ports()
    port = av.target_port

    if ex.get("is_local_only"):
        if pos["privilege"] == "none" and not pos["has_lan"]:
            return None, _gate("exposure",
                               "Локальное действие на хосте: одного сетевого доступа недостаточно, "
                               "нужен доступ к самому узлу — для внешнего атакующего недостижимо")
        return _factor("reachability", "Достижимость", 14,
                       "Инсайдер имеет доступ к хосту — локальное действие выполнимо"), None

    if ex.get("requires_lan"):
        if not pos["has_lan"]:
            return None, _gate("exposure",
                               "Атака требует позиции в одном L2-сегменте с жертвой (перехват/ретрансляция) — "
                               "из внешней сети недостижима")
        return _factor("reachability", "Достижимость", 12,
                       "Инсайдер находится в сегменте — перехват/ретрансляция возможны"), None

    if port is None:
        return _factor("reachability", "Достижимость", 6,
                       "Вектор не привязан к конкретному порту — базовая достижимость"), None

    if port in observed:
        return _factor("reachability", "Достижимость", 18,
                       f"Порт {port} подтверждён открытым сканером"), None

    if pos["has_lan"]:
        return _factor("reachability", "Достижимость", 4,
                       f"Порт {port} не наблюдался открытым, но во внутреннем сегменте может быть "
                       f"доступен — требуется проверка"), None

    return None, _gate("exposure", f"Порт {port} не наблюдался открытым снаружи — сервис недостижим")


def _service_live(av: AttackVector, ctx: ScanContext):
    if av.target_port is None:
        # локальное/пост-эксплуатационное действие — сетевого сервиса нет, проверять нечего
        return _factor("service_live", "Сервис активен", 0,
                       "Локальное действие — сетевой сервис не требуется")
    chk = engine.check_service(av, ctx)
    if chk.status == "pass":
        return _factor("service_live", "Сервис активен", 10, chk.evidence)
    if chk.status == "warn":
        return _factor("service_live", "Сервис активен", 3, chk.evidence,
                       verify="Подтвердить, что сервис на порту действительно запущен и доступен")
    if chk.status == "fail":
        return _factor("service_live", "Сервис активен", -8, chk.evidence)
    return _factor("service_live", "Сервис активен", 0, chk.evidence)


def _version(av: AttackVector, ctx: ScanContext, kb: Knowledge):
    """Возвращает (factor|None, gate|None, soft_cap|None)."""
    chk = engine.check_version(av, ctx, kb)
    if chk.status == "pass":
        return _factor("version_match", "Версия/продукт", 15, chk.evidence), None, None
    if chk.status == "fail":
        return None, _gate("version_match", chk.evidence), None
    if chk.status == "unknown":
        # CVE-backed, но версию/патч подтвердить нельзя -> нельзя признать полностью реализуемой
        return (_factor("version_match", "Версия/продукт", -6, chk.evidence,
                        verify="Подтвердить версию ПО и отсутствие патча для целевого CVE"),
                None, YELLOW_CAP)
    # na -> без CVE, проверка версии не применяется
    return None, None, None


def _exploit_maturity(ex: dict):
    m = (ex.get("exploit_maturity") or "tooling").lower()
    delta = _MATURITY_DELTA.get(m, 4)
    label = _MATURITY_LABEL.get(m, "инструментарий")
    return _factor("exploit_maturity", "Зрелость эксплойта", delta, f"Доступен {label}")


def _privilege_fit(ex: dict, pos: dict):
    req = (ex.get("min_privilege") or "none").lower()
    have = pos["privilege"]
    if privilege_rank(have) >= privilege_rank(req):
        if req == "none":
            return _factor("privilege_fit", "Требуемые привилегии", 0,
                           "Атака не требует предварительных прав")
        return _factor("privilege_fit", "Требуемые привилегии", 0,
                       f"Прав роли «{have}» достаточно (требуется не ниже «{req}»)")
    # прав не хватает
    if have == "none":
        return _factor("privilege_fit", "Требуемые привилегии", -25,
                       f"Требуются учётные данные/права «{req}», которых у внешнего атакующего нет")
    return _factor("privilege_fit", "Требуемые привилегии", -28,
                   f"Требуются права «{req}», у роли «{have}» их нет — нужно предварительное повышение привилегий")


def _mitigation(av: AttackVector, ctx: ScanContext, pos: dict):
    chk = engine.check_mitigation(av, ctx)
    if chk.status == "warn":
        if pos["perimeter"]:
            return _factor("mitigation", "Компенсирующие контроли", -10,
                           "Периметровые средства (брандмауэр/антивирус) могут детектировать или ограничить атаку")
        return _factor("mitigation", "Компенсирующие контроли", -5,
                       "Хостовые средства защиты могут детектировать атаку")
    # pass / прочее: явных контролей не обнаружено — нейтрально, фактов не выдумываем
    return _factor("mitigation", "Компенсирующие контроли", 0, chk.evidence)


def _severity(av: AttackVector, kb: Knowledge):
    sev = engine._severity_of(av, kb)
    delta = _SEVERITY_DELTA.get(sev, 0)
    return sev, _factor("severity", "Тяжесть (severity/CVSS)", delta, f"Уровень тяжести: {sev}")


# --------------------------------------------------------------------------- #
#  Сборка оценки по позиции
# --------------------------------------------------------------------------- #

def _verdict_from(score: int, gates: list[dict]) -> str:
    if gates:
        return VERDICT_NOT
    if score >= GREEN_MIN:
        return VERDICT_REALIZABLE
    if score >= YELLOW_MIN:
        return VERDICT_PARTIALLY
    return VERDICT_NOT


def _justification(verdict: str, color: str, label: str, score: int,
                   factors: list[dict], gates: list[dict], verify: list[str] | None = None) -> str:
    if gates:
        reasons = "; ".join(g["evidence"] for g in gates)
        return f"{label.capitalize()} ({color}): {reasons}. Итоговый балл {score}/100."
    contributors = sorted((f for f in factors if f["delta"] != 0),
                          key=lambda f: abs(f["delta"]), reverse=True)[:3]
    parts = []
    for f in contributors:
        sign = "+" if f["delta"] > 0 else ""
        parts.append(f"{f['evidence']} ({sign}{f['delta']})")
    body = "; ".join(parts) if parts else "значимых факторов не выявлено"
    # verify («что уточнить») отдаётся отдельным полем qualitative.verify,
    # чтобы не дублировать его в обосновании и показывать выделенной строкой.
    return (f"{label.capitalize()} ({color}): {body}. "
            f"Итог {score}/100 при пороге реализуемости {GREEN_MIN} и пороге возможности {YELLOW_MIN}.")


def score_position(av: AttackVector, ctx: ScanContext, kb: Knowledge,
                   methodics: Methodics, position: str) -> dict:
    pos = POSITION_META[position]
    ex = methodics.execution_for(av)

    factors: list[dict] = []
    gates: list[dict] = []
    soft_cap: int | None = None

    reach_f, reach_g = _reachability(av, ctx, ex, pos)
    if reach_g:
        gates.append(reach_g)
    if reach_f:
        factors.append(reach_f)

    factors.append(_service_live(av, ctx))

    ver_f, ver_g, ver_cap = _version(av, ctx, kb)
    if ver_g:
        gates.append(ver_g)
    if ver_f:
        factors.append(ver_f)
    if ver_cap is not None:
        soft_cap = ver_cap if soft_cap is None else min(soft_cap, ver_cap)

    factors.append(_exploit_maturity(ex))
    factors.append(_privilege_fit(ex, pos))
    factors.append(_mitigation(av, ctx, pos))
    severity, sev_f = _severity(av, kb)
    factors.append(sev_f)

    # Неопределённость исхода: сервис достижим и запущен, но успех зависит от того,
    # что по данным сканера проверить нельзя (пароль при переборе, реальное наличие
    # беспарольного доступа, отключённая подпись и жертва). Держим на «возможно».
    outcome = ex.get("outcome_uncertain")
    if outcome and not gates:
        factors.append(_factor("outcome", "Неопределённость исхода", 0, outcome, verify=outcome))

    # КЛЮЧЕВОЕ: любая неснятая неопределённость (у фактора есть «что уточнить»)
    # не даёт «зелёного» — держим на «возможно», пока не подтвердят. Иначе вышло бы
    # противоречие «реализуемо, но уточните, запущен ли сервис». Зелёный = всё
    # подтверждено и уточнять нечего; жёлтый = возможно + список verify.
    if not gates and any(f.get("verify") for f in factors):
        soft_cap = YELLOW_CAP if soft_cap is None else min(soft_cap, YELLOW_CAP)

    raw = BASE_SCORE + sum(f["delta"] for f in factors)
    score = _clamp(raw)
    capped = False
    if soft_cap is not None and score > soft_cap and not gates:
        score = soft_cap
        capped = True
    if gates:
        # балл оставляем информативным, но не выше красной зоны
        score = min(score, YELLOW_MIN - 1)

    verdict = _verdict_from(score, gates)
    color, label = _BAND[verdict]
    # «что уточнить, чтобы подтвердить реализуемость» — для красного это блокер (гейт),
    # для жёлтого — недостающие подтверждения, для зелёного — пусто.
    verify = [] if gates else _dedup([f["verify"] for f in factors if f.get("verify")])
    justification = _justification(verdict, color, label, score, factors, gates, verify)

    return {
        "position": position,
        "position_label": pos["label"],
        "position_group": pos["group"],
        "severity": severity,
        "numeric": {
            "score": score,
            "max": 100,
            "base": BASE_SCORE,
            "raw_sum": raw,
            "soft_cap_applied": (soft_cap if capped else None),
            "verdict": verdict,
            "band": color,
            "thresholds": {"realizable_min": GREEN_MIN, "possible_min": YELLOW_MIN},
            "factors": factors,
            "gates": gates,
        },
        "qualitative": {
            "label": label,
            "color": color,
            "justification": justification,
            "verify": verify,          # что уточнить, чтобы подтвердить реализуемость
        },
    }


def assess_all_positions(av: AttackVector, ctx: ScanContext, kb: Knowledge,
                         methodics: Methodics) -> dict:
    return {pos: score_position(av, ctx, kb, methodics, pos) for pos in POSITIONS}


def scoring_model_doc() -> dict:
    """Самоописание модели для блока meta отчёта (что и почему влияет на балл)."""
    return {
        "base_score": BASE_SCORE,
        "score_range": [0, 100],
        "thresholds": {
            "realizable_min": GREEN_MIN,
            "possible_min": YELLOW_MIN,
            "comment": (f">= {GREEN_MIN} -> реализуемо (зелёный); "
                        f"{YELLOW_MIN}..{GREEN_MIN - 1} -> возможно (жёлтый); "
                        f"< {YELLOW_MIN} или сработавший гейт -> не реализуемо (красный)"),
        },
        "factors": [
            {"key": "reachability", "meaning": "достижимость сервиса/узла из позиции атакующего",
             "range": "+4..+18, иначе гейт"},
            {"key": "service_live", "meaning": "подтверждён ли живой сервис", "range": "-8..+10"},
            {"key": "version_match", "meaning": "версия/продукт в уязвимом диапазоне",
             "range": "+15 при подтверждении, -6 и потолок жёлтой зоны при неизвестности, гейт при опровержении"},
            {"key": "exploit_maturity", "meaning": "зрелость средств эксплуатации", "range": "+2..+14"},
            {"key": "privilege_fit", "meaning": "хватает ли прав роли для проведения", "range": "-28..0"},
            {"key": "mitigation", "meaning": "компенсирующие контроли", "range": "-10..0"},
            {"key": "severity", "meaning": "тяжесть (severity/CVSS)", "range": "0..+8"},
        ],
        "gates": [
            "exposure — сервис/узел недостижим из данной позиции (или нужна L2-позиция/доступ к хосту)",
            "version_match — целевой продукт/версия опровергнут (не тот продукт или пропатчено)",
        ],
        "soft_cap": (f"балл ограничивается {YELLOW_CAP} (потолок жёлтой зоны), если нельзя подтвердить версию/патч "
                     f"ИЛИ исход зависит от непроверяемого (пароль при переборе, реальное наличие беспарольного "
                     f"доступа, отключённая подпись и жертва). Тогда вердикт — «возможно» с пометкой «что уточнить»."),
        "verify": "поле qualitative.verify — список того, что нужно подтвердить, чтобы повысить уверенность "
                  "(для жёлтого); для красного причина в gates.",
        "note": "Качественная оценка (слово+цвет) выводится из балла и гейтов детерминированно.",
    }
