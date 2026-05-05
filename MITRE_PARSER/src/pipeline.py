"""
Главный оркестратор парсера.

Стадии:
  1. fetch_all()         — параллельно скачать сырые файлы.
  2. parse_all()         — 4 парсера, выдают сырые dict-списки.
  3. cross_link()        — связывание CVE/CWE/CAPEC/ATT&CK/Software/Mitigations.
  4. translate_all()     — перевод текстовых полей всех записей на русский.
  5. build_attack_db()   — финальный tools_database.json.
  6. build_defense_db()  — финальный defense_database.json.
  7. write_all()         — атомарная запись в databases/ с бэкапом.

Поддерживает:
  - Инкрементальный режим (append) — дозапись новых записей
  - Checkpoint/resume — продолжение после прерывания
  - Progress callbacks для GUI
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from config import Config
from sources.http_loader import HttpLoader
from parsers.attack_parser import AttackStixParser
from parsers.capec_parser import CapecParser
from parsers.cwe_parser import CweParser
from parsers.cve_parser import CveParser
from enrichment.cross_linker import CrossLinker
from enrichment.attack_db_builder import AttackDbBuilder
from enrichment.defense_db_builder import DefenseDbBuilder
from translation.translator import Translator, is_russian
from translation.providers.base import BaseProvider
from db_writer import write_database
from state_manager import StateManager


# ── Поля, которые нужно переводить на русский ──────────────
_TEXT_FIELDS = {
    "capec": ["name", "description", "extended_description"],
    "capec_lists": ["prerequisites", "indicators", "resources_required",
                    "example_instances", "mitigations"],
    "cwe": ["name", "description", "extended_description", "mitigation"],
    "cwe_lists": ["demonstrative_examples"],
    "cve": ["description"],
    "attack": ["name", "description", "detection"],
    "attack_lists": ["mitigations"],
    "software": ["description"],
    "mitre_mit": ["name", "description"],
}

_REQUIRED_TOOLS = ["id", "name", "type", "applicable_attack_types", "commands"]
_REQUIRED_DEFENSE = ["id", "attack_type", "name", "tools"]


class Pipeline:
    def __init__(
        self,
        skip_translate: bool = False,
        only: list[str] | None = None,
        providers: list[BaseProvider] | None = None,
        limits: dict[str, int] | None = None,
        append_mode: bool = False,
        resume: bool = False,
        progress_callback: Callable[[str, int, int, str], None] | None = None,
        log_callback: Callable[[str], None] | None = None,
    ) -> None:
        Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        Config.CACHE_DIR.mkdir(parents=True, exist_ok=True)
        Config.PROJECT_DATABASES_DIR.mkdir(parents=True, exist_ok=True)

        self.skip_translate = skip_translate
        self.only = set(only or []) or None
        self.append_mode = append_mode
        self.resume = resume

        # User-configurable limits override Config defaults
        self.limits = {
            "capec": Config.MAX_CAPEC_RECORDS,
            "cwe": Config.MAX_CWE_RECORDS,
            "cve": Config.MAX_CVE_RECORDS,
            "attack": Config.MAX_ATTACK_RECORDS,
        }
        if limits:
            self.limits.update(limits)

        # Callbacks for GUI integration
        self.progress_callback = progress_callback
        self.log_callback = log_callback

        self.loader = HttpLoader()
        self.state = StateManager()

        def _translation_progress(done: int, total: int, label: str) -> None:
            if self.progress_callback:
                self.progress_callback("translate", done, total, label)

        self.translator = Translator(
            providers=providers or [],
            force_enable=not skip_translate,
            progress_callback=_translation_progress,
        )

        # Накопители
        self.raw: dict[str, Any] = {}
        self.capec: list[dict] = []
        self.cwe: list[dict] = []
        self.cve: list[dict] = []
        self.techniques: list[dict] = []
        self.software: list[dict] = []
        self.mitre_mit: list[dict] = []
        self.groups: list[dict] = []

        self._aborted = False

    # ── Logging ───────────────────────────────────────────
    def _log(self, msg: str) -> None:
        print(msg)
        if self.log_callback:
            self.log_callback(msg)

    def abort(self) -> None:
        """Signal pipeline to stop after current record."""
        self._aborted = True

    # ── Общие вспомогалки ─────────────────────────────────
    def _enabled(self, name: str) -> bool:
        if not self.only:
            return True
        return name in self.only

    def _load_existing(self, fname: str) -> list:
        path = Config.PROJECT_DATABASES_DIR / fname
        if not path.exists():
            return []
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except (OSError, json.JSONDecodeError) as e:
            self._log(f"  [Pipeline] Не удалось прочитать {fname}: {e}")
            return []

    def _existing_ids(self, fname: str) -> set[str]:
        """Get set of IDs already in a database file."""
        records = self._load_existing(fname)
        return {r.get("id") for r in records if isinstance(r, dict) and r.get("id")}

    # ── 1. Fetch ──────────────────────────────────────────
    def fetch_all(self) -> None:
        self._log("\n=== ЭТАП 1/7: Загрузка источников ===")
        if self.progress_callback:
            self.progress_callback("fetch", 0, 4, "")

        def _fetch_capec() -> bytes | None:
            return self.loader.fetch(Config.SOURCES["capec"])

        def _fetch_cwe() -> bytes | None:
            return self.loader.fetch_zip_member(Config.SOURCES["cwe"], ".xml")

        def _fetch_cve() -> dict | None:
            return self.loader.fetch_gz_json(Config.SOURCES["cve_latest"])

        def _fetch_attack() -> bytes | None:
            return self.loader.fetch(Config.SOURCES["attack_stix"])

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {
                "capec": pool.submit(_fetch_capec),
                "cwe": pool.submit(_fetch_cwe),
                "cve": pool.submit(_fetch_cve),
                "attack": pool.submit(_fetch_attack),
            }
            done = 0
            for name, fut in futures.items():
                try:
                    self.raw[name] = fut.result()
                except Exception as e:
                    self._log(f"  [Pipeline] Ошибка загрузки {name}: {e}")
                    self.raw[name] = None
                done += 1
                if self.progress_callback:
                    self.progress_callback("fetch", done, 4, name)

        sizes = {k: (len(v) if hasattr(v, "__len__") else "?") for k, v in self.raw.items()}
        self._log(f"  [Pipeline] Размеры: {sizes}")

    # ── 2. Parse ──────────────────────────────────────────
    def parse_all(self) -> None:
        self._log("\n=== ЭТАП 2/7: Парсинг ===")
        if self.progress_callback:
            self.progress_callback("parse", 0, 4, "")

        # Apply user limits via Config override
        Config.MAX_CAPEC_RECORDS = self.limits.get("capec", Config.MAX_CAPEC_RECORDS)
        Config.MAX_CWE_RECORDS = self.limits.get("cwe", Config.MAX_CWE_RECORDS)
        Config.MAX_CVE_RECORDS = self.limits.get("cve", Config.MAX_CVE_RECORDS)
        Config.MAX_ATTACK_RECORDS = self.limits.get("attack", Config.MAX_ATTACK_RECORDS)

        # In append mode, offset by existing record count
        capec_offset = 0
        cwe_offset = 0
        cve_offset = 0
        attack_offset = 0

        if self.append_mode:
            capec_offset = len(self._existing_ids(Config.DB_FILES["capec"]))
            cwe_offset = len(self._existing_ids(Config.DB_FILES["cwe"]))
            cve_offset = len(self._existing_ids(Config.DB_FILES["cve"]))
            attack_offset = len(self._existing_ids(Config.DB_FILES["attack"]))
            self._log(f"  [Append] Смещения: CAPEC={capec_offset}, CWE={cwe_offset}, "
                      f"CVE={cve_offset}, ATT&CK={attack_offset}")

        step = 0
        if self.raw.get("capec"):
            self.capec = CapecParser().parse(self.raw["capec"], offset=capec_offset)
            step += 1
            if self.progress_callback:
                self.progress_callback("parse", step, 4, "CAPEC")

        if self.raw.get("cwe"):
            self.cwe = CweParser().parse(self.raw["cwe"], offset=cwe_offset)
            step += 1
            if self.progress_callback:
                self.progress_callback("parse", step, 4, "CWE")

        if self.raw.get("cve"):
            self.cve = CveParser().parse(self.raw["cve"], offset=cve_offset)
            step += 1
            if self.progress_callback:
                self.progress_callback("parse", step, 4, "CVE")

        if self.raw.get("attack"):
            attack_bundle = AttackStixParser().parse(
                self.raw["attack"], offset=attack_offset
            )
            self.techniques = attack_bundle["techniques"]
            self.software = attack_bundle["software"]
            self.mitre_mit = attack_bundle["mitigations"]
            self.groups = attack_bundle["groups"]
            step += 1
            if self.progress_callback:
                self.progress_callback("parse", step, 4, "ATT&CK")

    # ── 3. Cross-link ─────────────────────────────────────
    def cross_link(self) -> None:
        self._log("\n=== ЭТАП 3/7: Связывание объектов ===")
        if self.progress_callback:
            self.progress_callback("link", 0, 1, "")

        linker = CrossLinker(
            capec=self.capec,
            cwe=self.cwe,
            cve=self.cve,
            techniques=self.techniques,
            software=self.software,
            mitre_mitigations=self.mitre_mit,
        )
        linker.run(passes=2)

        if self.progress_callback:
            self.progress_callback("link", 1, 1, "done")

    # ── 4. Translate ──────────────────────────────────────
    def translate_all(self) -> None:
        if self.skip_translate or not self.translator.enabled:
            self._log("\n=== ЭТАП 4/7: Перевод ПРОПУЩЕН ===")
            return
        self._log("\n=== ЭТАП 4/7: Перевод на русский ===")
        t0 = time.monotonic()

        # Check if resuming from a partial state
        checkpoint = self.state.load_checkpoint() if self.resume else None
        resume_stage = ""
        resume_progress = 0
        if checkpoint and checkpoint.stage == "translate":
            resume_stage = checkpoint.sub_stage
            resume_progress = checkpoint.progress
            self._log(f"  [Resume] Продолжаем с {resume_stage} #{resume_progress}")

        sections = [
            ("capec", self.capec, self._translate_capec_record),
            ("cwe", self.cwe, self._translate_cwe_record),
            ("cve", self.cve, self._translate_cve_record),
            ("attack", self.techniques, self._translate_attack_record),
            ("software", self.software, self._translate_software_record),
            ("mitigations", self.mitre_mit, self._translate_mitigation_record),
            ("groups", self.groups, self._translate_group_record),
        ]

        skip_until = resume_stage if resume_stage else ""
        skipping = bool(skip_until)

        for section_name, records, translate_fn in sections:
            if self._aborted:
                break
            if skipping:
                if section_name == skip_until:
                    skipping = False
                    # Skip already-translated records
                    records_slice = records[resume_progress:]
                    self._log(f"  -> {section_name} (продолжение с #{resume_progress}, "
                              f"осталось {len(records_slice)})")
                else:
                    # Load partial if available
                    partial = self.state.load_partial(section_name)
                    if partial:
                        self._log(f"  -> {section_name}: загружено из partial ({len(partial)})")
                    continue
            else:
                records_slice = records

            if not records_slice:
                continue

            self._log(f"  -> {section_name} ({len(records_slice)} записей)")
            self.state.update_stage("translate", section_name, 0, len(records_slice))

            def _checkpoint_fn(progress: int, _name=section_name, _recs=records) -> None:
                self.state.update_stage("translate", _name, progress, len(_recs))
                self.state.save_partial(_name, _recs)

            self.translator.translate_records_bidirectional(
                records_slice, translate_fn, label=section_name,
                checkpoint_fn=_checkpoint_fn,
            )
            self.state.save_partial(section_name, records)

        self.translator.flush()
        elapsed = time.monotonic() - t0
        self._log(f"  [Pipeline] Перевод завершён за {elapsed:.1f}s. "
                  f"Статистика: {self.translator.stats()}")

    def _translate_capec_record(self, rec: dict) -> None:
        self.translator.translate_dict(rec, _TEXT_FIELDS["capec"])
        self.translator.translate_dict(rec, _TEXT_FIELDS["capec_lists"])
        # Translate short label-like fields with original in parentheses
        self.translator.translate_dict_keep_original(
            rec, ["severity", "likelihood_of_attack", "typical_likelihood_of_exploit", "abstraction"]
        )
        for ex in rec.get("execution_flow", []) or []:
            self.translator.translate_dict(ex, ["phase", "description"])
            if ex.get("techniques"):
                ex["techniques"] = self.translator.translate_list(ex["techniques"])
        for cons in rec.get("consequences", []) or []:
            if cons.get("scope"):
                cons["scope"] = self.translator.translate_list(cons["scope"])
            if cons.get("impact"):
                cons["impact"] = self.translator.translate_list(cons["impact"])
            if cons.get("note"):
                cons["note"] = self.translator.translate(cons["note"])
        for sk in rec.get("skills_required", []) or []:
            if sk.get("description"):
                sk["description"] = self.translator.translate(sk["description"])
            if sk.get("level"):
                sk["level"] = self.translator.translate_keep_original(sk["level"])
        # Taxonomy mappings — translate entry_name and taxonomy with original
        for tm in rec.get("taxonomy_mappings", []) or []:
            if tm.get("entry_name"):
                tm["entry_name"] = self.translator.translate_keep_original(tm["entry_name"])
            if tm.get("taxonomy"):
                tm["taxonomy"] = self.translator.translate_keep_original(tm["taxonomy"])
            if tm.get("mapping_fit"):
                tm["mapping_fit"] = self.translator.translate_keep_original(tm["mapping_fit"])

    def _translate_cwe_record(self, rec: dict) -> None:
        self.translator.translate_dict(rec, _TEXT_FIELDS["cwe"])
        self.translator.translate_dict(rec, _TEXT_FIELDS["cwe_lists"])
        # Short label fields with original in parentheses
        self.translator.translate_dict_keep_original(
            rec, ["likelihood_of_exploit", "abstraction", "status"]
        )
        for cons in rec.get("common_consequences", []) or []:
            if cons.get("scope"):
                cons["scope"] = self.translator.translate_list(cons["scope"])
            if cons.get("impact"):
                cons["impact"] = self.translator.translate_list(cons["impact"])
            if cons.get("note"):
                cons["note"] = self.translator.translate(cons["note"])
        for moi in rec.get("modes_of_introduction", []) or []:
            if moi.get("phase"):
                moi["phase"] = self.translator.translate_keep_original(moi["phase"])
            if moi.get("note"):
                moi["note"] = self.translator.translate(moi["note"])
        for det in rec.get("detection_methods_detailed", []) or []:
            if det.get("method"):
                det["method"] = self.translator.translate_keep_original(det["method"])
            if det.get("description"):
                det["description"] = self.translator.translate(det["description"])
            if det.get("effectiveness"):
                det["effectiveness"] = self.translator.translate_keep_original(det["effectiveness"])
        for m in rec.get("mitigations_detailed", []) or []:
            if m.get("strategy"):
                m["strategy"] = self.translator.translate_keep_original(m["strategy"])
            for f in ("description", "effectiveness_notes"):
                if m.get(f):
                    m[f] = self.translator.translate(m[f])
            if m.get("effectiveness"):
                m["effectiveness"] = self.translator.translate_keep_original(m["effectiveness"])
            if m.get("phase"):
                m["phase"] = self.translator.translate_list(m["phase"])
        for ox in rec.get("observed_examples", []) or []:
            if ox.get("description"):
                ox["description"] = self.translator.translate(ox["description"])
        # Taxonomy mappings
        for tm in rec.get("taxonomy_mappings", []) or []:
            if tm.get("entry_name"):
                tm["entry_name"] = self.translator.translate_keep_original(tm["entry_name"])
            if tm.get("taxonomy"):
                tm["taxonomy"] = self.translator.translate_keep_original(tm["taxonomy"])
        # Applicable platforms
        for plat in rec.get("applicable_platforms", []) or []:
            if isinstance(plat, dict) and plat.get("name"):
                plat["name"] = self.translator.translate_keep_original(plat["name"])

    def _translate_cve_record(self, rec: dict) -> None:
        if rec.get("description") and not is_russian(rec["description"]):
            rec["description"] = self.translator.translate(rec["description"])
        # Short label fields with original
        self.translator.translate_dict_keep_original(
            rec, ["attack_type", "base_severity", "requires_service"]
        )
        # References descriptions
        for ref in rec.get("references", []) or []:
            if isinstance(ref, dict) and ref.get("description"):
                ref["description"] = self.translator.translate(ref["description"])

    def _translate_attack_record(self, rec: dict) -> None:
        self.translator.translate_dict(rec, _TEXT_FIELDS["attack"])
        self.translator.translate_dict(rec, _TEXT_FIELDS["attack_lists"])
        if rec.get("tactic"):
            rec["tactic"] = self.translator.translate_keep_original(rec["tactic"])
        if rec.get("tactics"):
            rec["tactics"] = [
                self.translator.translate_keep_original(t) for t in rec["tactics"]
            ]
        # Platforms, data_sources — short terms
        if rec.get("platforms"):
            rec["platforms"] = [
                self.translator.translate_keep_original(p) for p in rec["platforms"]
            ]
        if rec.get("data_sources"):
            rec["data_sources"] = [
                self.translator.translate_keep_original(ds) for ds in rec["data_sources"]
            ]
        for m in rec.get("mitigations_detailed", []) or []:
            if m.get("name"):
                m["name"] = self.translator.translate_keep_original(m["name"])
            if m.get("description"):
                m["description"] = self.translator.translate(m["description"])
        # Procedures/examples
        for proc in rec.get("procedures", []) or []:
            if isinstance(proc, dict) and proc.get("description"):
                proc["description"] = self.translator.translate(proc["description"])

    def _translate_software_record(self, rec: dict) -> None:
        self.translator.translate_dict(rec, _TEXT_FIELDS["software"])

    def _translate_mitigation_record(self, rec: dict) -> None:
        self.translator.translate_dict(rec, _TEXT_FIELDS["mitre_mit"])

    def _translate_group_record(self, rec: dict) -> None:
        self.translator.translate_dict(rec, ["name", "description"])

    # ── 5/6/7. Build & write ─────────────────────────────
    def write_all(self) -> None:
        self._log("\n=== ЭТАП 5-7/7: Сборка и запись баз ===")
        out_dir = Config.PROJECT_DATABASES_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        if self.progress_callback:
            self.progress_callback("write", 0, 6, "")

        step = 0
        if self._enabled("capec") and self.capec:
            write_database(out_dir / Config.DB_FILES["capec"], self.capec,
                           name="CAPEC", append=self.append_mode)
            step += 1
            if self.progress_callback:
                self.progress_callback("write", step, 6, "CAPEC")

        if self._enabled("cwe") and self.cwe:
            write_database(out_dir / Config.DB_FILES["cwe"], self.cwe,
                           name="CWE", append=self.append_mode)
            step += 1
            if self.progress_callback:
                self.progress_callback("write", step, 6, "CWE")

        if self._enabled("cve") and self.cve:
            write_database(out_dir / Config.DB_FILES["cve"], self.cve,
                           name="CVE", append=self.append_mode)
            step += 1
            if self.progress_callback:
                self.progress_callback("write", step, 6, "CVE")

        if self._enabled("attack") and self.techniques:
            write_database(out_dir / Config.DB_FILES["attack"], self.techniques,
                           name="ATT&CK", append=self.append_mode)
            step += 1
            if self.progress_callback:
                self.progress_callback("write", step, 6, "ATT&CK")

        if self._enabled("tools"):
            self._log("\n  > Сборка tools_database.json...")
            existing_tools = self._load_existing(Config.DB_FILES["tools"])
            tools = AttackDbBuilder().build(
                techniques=self.techniques,
                software=self.software,
                existing_tools=existing_tools,
            )
            write_database(out_dir / Config.DB_FILES["tools"], tools,
                           required_fields=_REQUIRED_TOOLS, name="Tools")
            step += 1
            if self.progress_callback:
                self.progress_callback("write", step, 6, "Tools")

        if self._enabled("defense"):
            self._log("\n  > Сборка defense_database.json...")
            existing_def = self._load_existing(Config.DB_FILES["defense"])
            defense = DefenseDbBuilder().build(
                techniques=self.techniques,
                mitre_mitigations=self.mitre_mit,
                cve=self.cve,
                existing_defense=existing_def,
            )
            write_database(out_dir / Config.DB_FILES["defense"], defense,
                           required_fields=_REQUIRED_DEFENSE, name="Defense")
            step += 1
            if self.progress_callback:
                self.progress_callback("write", step, 6, "Defense")

        # Дамп вспомогательных файлов
        try:
            with (Config.OUTPUT_DIR / "mitre_software.json").open("w", encoding="utf-8") as f:
                json.dump(self.software, f, ensure_ascii=False, indent=2)
            with (Config.OUTPUT_DIR / "mitre_mitigations.json").open("w", encoding="utf-8") as f:
                json.dump(self.mitre_mit, f, ensure_ascii=False, indent=2)
            with (Config.OUTPUT_DIR / "mitre_groups.json").open("w", encoding="utf-8") as f:
                json.dump(self.groups, f, ensure_ascii=False, indent=2)
        except OSError as e:
            self._log(f"  [Pipeline] Дамп вспомогательных файлов не удался: {e}")

        self.translator.flush()

    # ── Run ───────────────────────────────────────────────
    def run(self) -> None:
        t0 = time.monotonic()
        self._log("=" * 70)
        self._log(" MITRE PARSER 2.0 — переводимые расширенные базы кибербезопасности")
        self._log("=" * 70)
        self._log(f"  Output dir   : {Config.OUTPUT_DIR}")
        self._log(f"  Databases dir: {Config.PROJECT_DATABASES_DIR}")
        self._log(f"  Translate    : {self.translator.enabled}")
        self._log(f"  Mode         : {'append' if self.append_mode else 'new'}")
        self._log(f"  Limits       : {self.limits}")
        self._log(f"  Only         : {sorted(self.only) if self.only else 'ALL'}")

        settings = {
            "limits": self.limits,
            "append_mode": self.append_mode,
            "skip_translate": self.skip_translate,
        }

        # Check for resume
        if self.resume and self.state.has_checkpoint():
            cp = self.state.load_checkpoint()
            if cp:
                self._log(f"\n  [Resume] Найден checkpoint: {cp.run_id}, "
                          f"этап={cp.stage}/{cp.sub_stage}, прогресс={cp.progress}")
        else:
            self.state.start_run(settings)

        try:
            checkpoint = self.state.load_checkpoint()
            completed = checkpoint.completed_stages if checkpoint else []

            if "fetch" not in completed:
                self.fetch_all()
                self.state.complete_stage("fetch")
            else:
                self._log("\n  [Resume] Загрузка: пропуск (уже выполнено)")
                self.fetch_all()  # Need raw data anyway

            if self._aborted:
                return

            if "parse" not in completed:
                self.parse_all()
                self.state.complete_stage("parse")
            else:
                self._log("\n  [Resume] Парсинг: пропуск (уже выполнено)")
                self.parse_all()  # Need parsed data

            if self._aborted:
                return

            if "link" not in completed:
                self.cross_link()
                self.state.complete_stage("link")
            else:
                self._log("\n  [Resume] Связывание: пропуск (уже выполнено)")
                self.cross_link()

            if self._aborted:
                return

            if "translate" not in completed:
                self.translate_all()
                self.state.complete_stage("translate")

            if self._aborted:
                return

            self.write_all()
            self.state.complete_stage("write")

        except KeyboardInterrupt:
            self._log("\n  [Pipeline] Прервано. Сохраняем промежуточные результаты...")
            self.translator.flush()
            self.state.abort_run()
            raise
        except Exception:
            self.translator.flush()
            self.state.abort_run()
            raise
        finally:
            self.translator.flush()

        # Mark run as completed
        records = {
            "capec": len(self.capec),
            "cwe": len(self.cwe),
            "cve": len(self.cve),
            "attack": len(self.techniques),
            "software": len(self.software),
            "mitigations": len(self.mitre_mit),
        }
        provider_names = [p.name for p in self.translator.get_healthy_providers()]
        self.state.finish_run(records, provider_names,
                              mode="append" if self.append_mode else "new")

        self._log("\n" + "=" * 70)
        self._log(f" ГОТОВО за {time.monotonic() - t0:.1f}s")
        self._log("=" * 70)
        self._log(f"  CAPEC: {len(self.capec)}  CWE: {len(self.cwe)}  "
                  f"CVE: {len(self.cve)}  ATT&CK: {len(self.techniques)}")
        self._log(f"  MITRE software: {len(self.software)}  "
                  f"mitigations: {len(self.mitre_mit)}  groups: {len(self.groups)}")


__all__ = ["Pipeline"]
