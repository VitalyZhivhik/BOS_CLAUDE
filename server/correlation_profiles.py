import json
import os
import re
from datetime import datetime
from typing import Any, Optional


REQUIRED_FIELDS = [
    "max_score",
    "feasible_threshold",
    "partially_feasible_threshold",
    "not_feasible_threshold",
    "network_weight",
    "trivy_weight",
    "software_weight",
    "scanner_weight",
]

OPTIONAL_FIELDS_WITH_DEFAULTS = {
    "patch_weight": 10,
    "protection_weight": 5,
}


def profiles_dir(base_dir: str) -> str:
    return os.path.join(base_dir, "profiles")


def _safe_filename(name: str) -> str:
    base = (name or "").strip().lower()
    base = re.sub(r"\s+", "_", base)
    base = re.sub(r"[^a-z0-9_\\-]+", "", base)
    base = re.sub(r"_+", "_", base).strip("_")
    return base or "profile"


def _ensure_profile_defaults(profile: dict) -> dict:
    out = dict(profile or {})
    for k, v in OPTIONAL_FIELDS_WITH_DEFAULTS.items():
        if k not in out:
            out[k] = v
    return out


def validate_profile(profile: dict) -> Optional[str]:
    if not isinstance(profile, dict):
        return "profile должен быть объектом"
    for field in REQUIRED_FIELDS:
        if field not in profile:
            return f"Отсутствует обязательное поле: {field}"
    return None


def list_profiles(base_dir: str) -> list[dict]:
    out: list[dict] = []
    pdir = profiles_dir(base_dir)
    if not os.path.isdir(pdir):
        return out
    for fname in sorted(os.listdir(pdir)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(pdir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if validate_profile(data):
                continue
            data = _ensure_profile_defaults(data)
            out.append(
                {
                    "id": fname,
                    "file": fname,
                    "path": fpath,
                    "name": str(data.get("name") or fname.replace(".json", "")),
                    "description": str(data.get("description") or ""),
                    "settings": {k: data.get(k) for k in (REQUIRED_FIELDS + list(OPTIONAL_FIELDS_WITH_DEFAULTS.keys()))},
                }
            )
        except Exception:
            continue
    return out


def load_profile(base_dir: str, profile_id: str) -> dict:
    pid = str(profile_id or "").strip()
    if not pid or "/" in pid or "\\" in pid:
        raise ValueError("Некорректный profile_id")
    if not pid.endswith(".json"):
        pid = pid + ".json"
    fpath = os.path.join(profiles_dir(base_dir), pid)
    with open(fpath, "r", encoding="utf-8") as f:
        data = json.load(f)
    err = validate_profile(data)
    if err:
        raise ValueError(err)
    return _ensure_profile_defaults(data)


def save_profile(
    base_dir: str,
    name: str,
    description: str,
    settings: dict[str, Any],
    profile_id: Optional[str] = None,
) -> dict:
    if not isinstance(settings, dict):
        raise ValueError("settings должен быть объектом")

    profile = {
        "name": str(name or "").strip() or "Профиль",
        "description": str(description or "").strip(),
    }
    for k in REQUIRED_FIELDS:
        profile[k] = settings.get(k)
    for k, dv in OPTIONAL_FIELDS_WITH_DEFAULTS.items():
        profile[k] = settings.get(k, dv)

    err = validate_profile(profile)
    if err:
        raise ValueError(err)

    if profile_id:
        pid = str(profile_id).strip()
        if "/" in pid or "\\" in pid:
            raise ValueError("Некорректный profile_id")
        if not pid.endswith(".json"):
            pid = pid + ".json"
    else:
        pid = _safe_filename(profile["name"]) + ".json"

    pdir = profiles_dir(base_dir)
    os.makedirs(pdir, exist_ok=True)
    fpath = os.path.join(pdir, pid)
    tmp = fpath + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(profile, f, ensure_ascii=False, indent=2)
    os.replace(tmp, fpath)

    return {
        "id": pid,
        "file": pid,
        "path": fpath,
        "saved_at": datetime.now().isoformat(),
    }


def delete_profile(base_dir: str, profile_id: str) -> bool:
    pid = str(profile_id or "").strip()
    if not pid or "/" in pid or "\\" in pid:
        raise ValueError("Некорректный profile_id")
    if not pid.endswith(".json"):
        pid = pid + ".json"
    fpath = os.path.join(profiles_dir(base_dir), pid)
    if not os.path.exists(fpath):
        return False
    os.remove(fpath)
    return True

