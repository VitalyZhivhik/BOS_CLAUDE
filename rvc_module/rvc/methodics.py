"""Доступ к курируемой базе методичек (rvc/methodics_kb.json).

Слоистое описание ЛЮБЫХ данных (важно: софт запускают на разных стендах):
  1) product — продукто-специфичное семейство (совпадение по CVE или алиасу
     в имени): точная методичка (EternalBlue, Zerologon, MySQL и т.п.);
  2) type    — обобщённая методичка по КЛАССУ атаки (по attack_type): корректная
     универсальная (RCE/brute/relay/...), когда конкретного семейства нет —
     НЕ подменяем чужим продуктом;
  3) generic — универсальный порядок исследования, когда тип не распознан вовсе.

Каждый ответ несёт `basis` (product|type|generic), чтобы на дашборде честно
показать, под конкретный продукт методичка или обобщённая.
Профиль выполнения (execution) тоже берётся слоисто — это даёт объективную
численную оценку даже для незнакомых сервисов.
"""

from __future__ import annotations

import json
import os
import re

from .models import AttackVector

_KB_PATH = os.path.join(os.path.dirname(__file__), "methodics_kb.json")


def _norm(text: str) -> str:
    """Нормализует строку для сопоставления алиасов: пунктуация -> пробел, схлоп пробелов."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", (text or "").lower())).strip()


class Methodics:
    """Только чтение методичек и профилей выполнения (слоисто)."""

    def __init__(self, path: str = _KB_PATH):
        with open(path, encoding="utf-8") as fh:
            self._kb = json.load(fh)
        self.families: dict = self._kb.get("families", {})
        self.type_methodics: dict = self._kb.get("type_methodics", {})
        self.snapshot = self._kb.get("_meta", {}).get("snapshot", "unknown")
        self.disclaimer = self._kb.get("_meta", {}).get("disclaimer", "")
        self._by_cve: dict[str, str] = {}
        for key, fam in self.families.items():
            for cve in fam.get("cves", []):
                self._by_cve[cve.upper()] = key

    # ---- слой 1: продукто-специфичное семейство ---------------------------- #

    def specific_family_key(self, av: AttackVector) -> str | None:
        for cve in av.cve_ids:
            key = self._by_cve.get(cve.upper())
            if key:
                return key
        haystack = _norm(f"{av.name} {av.target_service} {av.attack_type}")
        for key, fam in self.families.items():
            for alias in fam.get("aliases", []):
                if _norm(alias) in haystack:
                    return key
        return None

    # ---- слоистое разрешение ----------------------------------------------- #

    def resolve(self, av: AttackVector) -> dict:
        """Возвращает {key, title, basis, execution, attack_methodic, defense_methodic}."""
        key = self.specific_family_key(av)
        if key:
            fam = self.families[key]
            return {
                "key": key, "title": fam.get("title", ""), "basis": "product",
                "execution": fam.get("execution", {}),
                "attack_methodic": fam.get("attack_methodic", {}),
                "defense_methodic": fam.get("defense_methodic", {}),
            }
        atype = (av.attack_type or "").lower()
        tm = self.type_methodics.get(atype)
        if tm:
            return {
                "key": f"type:{atype}", "title": tm.get("title", ""), "basis": "type",
                "execution": tm.get("execution", {}),
                "attack_methodic": tm.get("attack_methodic", {}),
                "defense_methodic": tm.get("defense_methodic", {}),
            }
        d = self.type_methodics.get("_default", {})
        return {
            "key": "generic", "title": d.get("title", ""), "basis": "generic",
            "execution": d.get("execution", {}),
            "attack_methodic": d.get("attack_methodic", {}),
            "defense_methodic": d.get("defense_methodic", {}),
        }

    # ---- удобные обёртки ---------------------------------------------------- #

    def family_key_for(self, av: AttackVector) -> str | None:
        """Ключ ПРОДУКТО-специфичного семейства (или None) — для поля report.family."""
        return self.specific_family_key(av)

    def family_for(self, av: AttackVector) -> tuple[str | None, dict]:
        r = self.resolve(av)
        return r["key"], {"title": r["title"]}

    def execution_for(self, av: AttackVector) -> dict:
        ex = self.resolve(av).get("execution")
        if ex:
            return ex
        return {"min_privilege": "none", "requires_lan": False, "is_local_only": False,
                "exploit_maturity": "tooling", "note": "Профиль по умолчанию."}

    def attack_methodic_for(self, av: AttackVector) -> dict:
        return self.resolve(av).get("attack_methodic", {})

    def defense_methodic_for(self, av: AttackVector) -> dict:
        return self.resolve(av).get("defense_methodic", {})

    def title_for(self, av: AttackVector) -> str:
        return self.resolve(av).get("title", "")

    def basis_for(self, av: AttackVector) -> str:
        return self.resolve(av).get("basis", "generic")
