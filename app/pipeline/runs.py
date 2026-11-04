"""Çalıştırma klasörleri: her çalıştırma runs/<id>/ altında tutulur.

runs/<id>/
    meta.json   hedef, oluşturulma zamanı, tamamlanan adımlar
    raw/        ham tarama çıktıları (U2)
"""

import datetime
import json
import re

from config import RUNS_DIR

RUN_ID_RE = re.compile(r"^\d{8}-\d{6}(-\d+)?$")


def run_dir(run_id):
    # run_id dışarıdan gelse bile klasör dışına çıkılamasın
    if not RUN_ID_RE.match(run_id):
        raise ValueError(f"Geçersiz çalıştırma kimliği: {run_id!r}")
    return RUNS_DIR / run_id


def new_run(target_key):
    """Yeni bir çalıştırma klasörü oluşturur, kimliğini döndürür."""
    base = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_id, n = base, 1
    while (RUNS_DIR / run_id).exists():   # aynı saniyede ikinci çalıştırma
        n += 1
        run_id = f"{base}-{n}"
    d = RUNS_DIR / run_id
    (d / "raw").mkdir(parents=True)
    save_meta(run_id, {
        "run_id": run_id,
        "target": target_key,
        "created": datetime.datetime.now().isoformat(timespec="seconds"),
        "steps": {},
    })
    return run_id


def load_meta(run_id):
    with open(run_dir(run_id) / "meta.json", encoding="utf-8") as f:
        return json.load(f)


def save_meta(run_id, meta):
    with open(run_dir(run_id) / "meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


def list_runs(target_key=None):
    """Mevcut çalıştırmalar, en yeni önce."""
    if not RUNS_DIR.exists():
        return []
    runs = []
    for d in RUNS_DIR.iterdir():
        if d.is_dir() and RUN_ID_RE.match(d.name) and (d / "meta.json").exists():
            try:
                meta = load_meta(d.name)
            except (OSError, json.JSONDecodeError):
                continue
            if target_key is None or meta.get("target") == target_key:
                runs.append(meta)
    return sorted(runs, key=lambda m: m["run_id"], reverse=True)
