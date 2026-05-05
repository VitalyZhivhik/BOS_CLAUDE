"""
LLM-обогащение баз tools_database и defense_database.

Использует LLM-провайдеров (Groq, Mistral, OpenRouter) для генерации
новых уникальных записей на основе знаний модели о кибербезопасности.
Модель генерирует записи в нужном JSON-формате, которые затем дозаписываются в базы.
"""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from config import Config
from translation.providers.base import BaseProvider


_TOOLS_PROMPT = '''You are a cybersecurity expert. Generate {count} NEW unique hacking/pentest tools for a tools database.
Each tool must be a JSON object with EXACTLY these fields:
- "id": unique string like "TOOL-LLM-XXX" (use numbers {start_id} to {end_id})
- "name": tool name (e.g. "Gobuster", "CrackMapExec")
- "type": one of: exploitation, reconnaissance, credential_cracking, lateral_movement, persistence, privilege_escalation, exfiltration, evasion, social_engineering, wireless, web_exploitation, reverse_engineering
- "description": detailed description IN RUSSIAN (2-3 sentences)
- "url": official URL or GitHub link
- "applicable_attack_types": list of attack types (e.g. ["brute_force", "web_exploitation"])
- "applicable_cve": empty list []
- "commands": object with "default" key containing list of command examples as strings (IN RUSSIAN comments + actual commands)
- "phases": list of attack phases IN RUSSIAN
- "skill_level": "Beginner" / "Intermediate" / "Advanced"
- "os": list of supported OS ["Linux", "Windows", "macOS"]
- "language": "ru"

IMPORTANT:
- DO NOT include these already existing tools: {existing_names}
- Commands must be practical, real examples
- Description and comments MUST be in Russian
- Return ONLY a valid JSON array, no markdown or explanations

Generate {count} tools:'''

_DEFENSE_PROMPT = '''You are a cybersecurity defense expert. Generate {count} NEW unique defense measures for a security database.
Each defense must be a JSON object with EXACTLY these fields:
- "id": unique string like "DEF-LLM-XXX" (use numbers {start_id} to {end_id})
- "attack_type": type of attack this defends against (e.g. "lateral_movement", "privilege_escalation", "data_exfiltration", "ransomware", "supply_chain_attack", "zero_day_exploit")
- "cve_ids": list of relevant CVE IDs if applicable, or empty []
- "name": short name IN RUSSIAN
- "description": detailed description IN RUSSIAN (2-3 sentences about what this defense does)
- "tools": list of tool objects, each with:
  - "name": tool/method name
  - "description": what it does IN RUSSIAN
  - "commands": list of command strings (Russian comments + actual commands)
- "priority": "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
- "effort": "Low" / "Medium" / "High"
- "effectiveness": "High" / "Medium" / "Low"
- "language": "ru"

IMPORTANT:
- DO NOT duplicate these existing defenses: {existing_names}
- Focus on: {focus_areas}
- Commands must be real, practical Windows/Linux examples
- All text MUST be in Russian
- Return ONLY a valid JSON array, no markdown

Generate {count} defenses:'''

_DEFENSE_FOCUS_AREAS = [
    "защита от ransomware", "защита цепочки поставок", "мониторинг DNS",
    "защита контейнеров Docker/K8s", "защита от supply-chain атак",
    "защита облачных сред AWS/Azure", "защита от фишинга",
    "защита от утечки данных (DLP)", "защита Active Directory",
    "защита от бесфайловых атак", "Zero Trust архитектура",
    "защита IoT устройств", "защита от инсайдерских угроз",
    "защита CI/CD пайплайнов", "защита от атак на API",
]


class LlmEnricher:
    """Uses LLM providers to generate new tools/defense records."""

    def __init__(
        self,
        provider: BaseProvider,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> None:
        self.provider = provider
        self.progress_callback = progress_callback
        self._generated_tools: list[dict] = []
        self._generated_defense: list[dict] = []

    def generate_tools(self, count: int, existing: list[dict]) -> list[dict]:
        """Generate new tool entries using LLM."""
        existing_names = [r.get("name", "") for r in existing][:100]
        existing_ids = {r.get("id", "") for r in existing}

        # Find next ID
        max_num = 0
        for eid in existing_ids:
            parts = eid.replace("TOOL-LLM-", "").replace("TOOL-SEED-", "")
            try:
                max_num = max(max_num, int(parts))
            except (ValueError, TypeError):
                pass

        start_id = max_num + 1
        results: list[dict] = []
        batch_size = min(count, 5)  # LLM works better with smaller batches

        for batch_start in range(0, count, batch_size):
            batch_count = min(batch_size, count - batch_start)
            s_id = start_id + batch_start
            e_id = s_id + batch_count - 1

            prompt = _TOOLS_PROMPT.format(
                count=batch_count,
                start_id=s_id,
                end_id=e_id,
                existing_names=", ".join(existing_names[:50]),
            )

            raw = self.provider.translate_text(prompt)
            if raw:
                parsed = self._parse_json_array(raw)
                for item in parsed:
                    if self._validate_tool(item) and item.get("id") not in existing_ids:
                        results.append(item)
                        existing_ids.add(item["id"])

            if self.progress_callback:
                self.progress_callback(
                    min(batch_start + batch_count, count), count, "tools"
                )
            time.sleep(1)

        self._generated_tools = results
        return results

    def generate_defense(self, count: int, existing: list[dict]) -> list[dict]:
        """Generate new defense entries using LLM."""
        existing_names = [r.get("name", "") for r in existing][:80]
        existing_ids = {r.get("id", "") for r in existing}

        max_num = 0
        for eid in existing_ids:
            parts = eid.replace("DEF-LLM-", "").replace("DEF-", "")
            try:
                max_num = max(max_num, int(parts))
            except (ValueError, TypeError):
                pass

        start_id = max_num + 1
        results: list[dict] = []
        batch_size = min(count, 3)

        focus_idx = 0
        for batch_start in range(0, count, batch_size):
            batch_count = min(batch_size, count - batch_start)
            s_id = start_id + batch_start
            e_id = s_id + batch_count - 1

            focus = _DEFENSE_FOCUS_AREAS[focus_idx % len(_DEFENSE_FOCUS_AREAS)]
            focus_idx += 1

            prompt = _DEFENSE_PROMPT.format(
                count=batch_count,
                start_id=s_id,
                end_id=e_id,
                existing_names=", ".join(existing_names[:40]),
                focus_areas=focus,
            )

            raw = self.provider.translate_text(prompt)
            if raw:
                parsed = self._parse_json_array(raw)
                for item in parsed:
                    if self._validate_defense(item) and item.get("id") not in existing_ids:
                        results.append(item)
                        existing_ids.add(item["id"])

            if self.progress_callback:
                self.progress_callback(
                    min(batch_start + batch_count, count), count, "defense"
                )
            time.sleep(1)

        self._generated_defense = results
        return results

    @staticmethod
    def _parse_json_array(text: str) -> list[dict]:
        """Try to parse JSON array from LLM response."""
        text = text.strip()

        # Remove markdown code fences
        if text.startswith("```"):
            lines = text.split("\n")
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)

        # Try direct parse
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)]
            if isinstance(data, dict):
                return [data]
        except json.JSONDecodeError:
            pass

        # Try to find JSON array in text
        start = text.find("[")
        end = text.rfind("]")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start:end + 1])
                if isinstance(data, list):
                    return [x for x in data if isinstance(x, dict)]
            except json.JSONDecodeError:
                pass

        return []

    @staticmethod
    def _validate_tool(item: dict) -> bool:
        required = ["id", "name", "type", "description", "commands"]
        return all(item.get(k) for k in required)

    @staticmethod
    def _validate_defense(item: dict) -> bool:
        required = ["id", "attack_type", "name", "description", "tools"]
        return all(item.get(k) for k in required)


__all__ = ["LlmEnricher"]
