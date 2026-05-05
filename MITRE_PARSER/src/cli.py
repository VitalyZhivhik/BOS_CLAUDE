"""
Точка входа в парсер (CLI-режим).

Примеры запуска (из MITRE_PARSER/):
  python src/cli.py
  python src/cli.py --skip-translate
  python src/cli.py --only tools defense
  python src/cli.py --append --limit-cve 500

Для GUI-версии используйте:
  python src/gui_app.py

Доступные значения --only:
  capec, cwe, cve, attack, tools, defense
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from pipeline import Pipeline  # noqa: E402
from translation.providers.google_provider import GoogleProvider  # noqa: E402
from translation.providers.groq_provider import GroqProvider  # noqa: E402
from translation.providers.mistral_provider import MistralProvider  # noqa: E402
from translation.providers.openrouter_provider import OpenRouterProvider  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="mitre-parser",
        description=(
            "Парсер MITRE ATT&CK / CAPEC / CWE / CVE с переводом на русский. "
            "Генерирует расширенные базы в databases/."
        ),
    )
    p.add_argument(
        "--skip-translate",
        action="store_true",
        help="Не выполнять автоматический перевод (быстрый прогон).",
    )
    p.add_argument(
        "--only",
        nargs="+",
        choices=["capec", "cwe", "cve", "attack", "tools", "defense"],
        help="Сохранить только указанные базы (остальные не пишутся).",
    )
    p.add_argument(
        "--append",
        action="store_true",
        help="Дозаписать новые уникальные записи к существующим базам.",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="Продолжить прерванный запуск (если есть checkpoint).",
    )
    p.add_argument("--limit-capec", type=int, default=None, help="Лимит CAPEC записей")
    p.add_argument("--limit-cwe", type=int, default=None, help="Лимит CWE записей")
    p.add_argument("--limit-cve", type=int, default=None, help="Лимит CVE записей")
    p.add_argument("--limit-attack", type=int, default=None, help="Лимит ATT&CK записей")
    p.add_argument(
        "--provider",
        nargs="+",
        choices=["google", "groq1", "groq2", "mistral", "openrouter"],
        default=["google"],
        help="Провайдеры перевода (по умолчанию: google).",
    )
    p.add_argument(
        "--openrouter-key",
        default="",
        help="API ключ для OpenRouter.",
    )
    p.add_argument(
        "--openrouter-model",
        default="meta-llama/llama-3.3-70b-instruct:free",
        help="Модель для OpenRouter.",
    )

    args = p.parse_args(argv)

    # Build limits
    limits: dict[str, int] = {}
    if args.limit_capec is not None:
        limits["capec"] = args.limit_capec
    if args.limit_cwe is not None:
        limits["cwe"] = args.limit_cwe
    if args.limit_cve is not None:
        limits["cve"] = args.limit_cve
    if args.limit_attack is not None:
        limits["attack"] = args.limit_attack

    # Build providers
    providers = []
    if not args.skip_translate:
        for name in args.provider:
            if name == "google":
                providers.append(GoogleProvider())
            elif name == "groq1":
                key = (os.environ.get("MP_GROQ_API_KEY_1") or "").strip()
                if key:
                    providers.append(GroqProvider(api_key=key, key_label="ключ 1"))
                else:
                    print("  [CLI] MP_GROQ_API_KEY_1 не задан, пропускаем groq1")
            elif name == "groq2":
                key = (os.environ.get("MP_GROQ_API_KEY_2") or "").strip()
                if key:
                    providers.append(GroqProvider(api_key=key, key_label="ключ 2"))
                else:
                    print("  [CLI] MP_GROQ_API_KEY_2 не задан, пропускаем groq2")
            elif name == "mistral":
                key = (os.environ.get("MP_MISTRAL_API_KEY") or "").strip()
                if key:
                    providers.append(MistralProvider(api_key=key))
                else:
                    print("  [CLI] MP_MISTRAL_API_KEY не задан, пропускаем mistral")
            elif name == "openrouter":
                if args.openrouter_key:
                    providers.append(OpenRouterProvider(
                        api_key=args.openrouter_key,
                        model=args.openrouter_model,
                    ))
                else:
                    print("  [CLI] --openrouter-key не указан, пропускаем OpenRouter")

    pipeline = Pipeline(
        skip_translate=args.skip_translate,
        only=args.only,
        providers=providers,
        limits=limits if limits else None,
        append_mode=args.append,
        resume=args.resume,
    )
    try:
        pipeline.run()
    except KeyboardInterrupt:
        print("\n[CLI] Прервано пользователем.")
        pipeline.translator.flush()
        return 130
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\n[CLI] Критическая ошибка: {e}")
        pipeline.translator.flush()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
