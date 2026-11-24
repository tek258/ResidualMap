"""Çalıştırma klasörleri: her çalıştırma runs/<id>/ altında tutulur.

runs/<id>/
    meta.json   hedef, oluşturulma zamanı, tamamlanan adımlar
    raw/        ham tarama çıktıları (U2)
"""

import datetime
import json
import re

from config import RUNS_DIR
from pipeline import dosya

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


def ornek_veriyle_baslat(target_key):
    """Docker ve tarama olmadan çalışan çalıştırma (demo B planı).

    inventory/raw/ altındaki ham dosyalar bu çalıştırmanın raw/ klasörüne kopyalanır ve
    2. adım "Repodaki dosya" yöntemiyle tamamlanmış sayılır. Sonraki adımlar normal akışla
    aynı kodu çalıştırır. Dönüş: (run_id, {kaynak: Sonuc}).
    """
    from pipeline import scans   # döngüsel içe aktarmayı önlemek için burada

    run_id = new_run(target_key)
    raw_dir = run_dir(run_id) / "raw"
    meta = load_meta(run_id)
    meta["ornek_veri"] = True
    sonuclar, tarama = {}, {}
    for kaynak in scans.RAW_FILES:
        sonuc = scans.yukle_repodan(kaynak, raw_dir)
        sonuclar[kaynak] = sonuc
        tarama[kaynak] = {
            "yontem": "Repodaki dosya (örnek veri)", "ok": sonuc.ok, "mesaj": sonuc.mesaj,
            "sure_sn": 0.0, "ozet": sonuc.ozet,
            "zaman": datetime.datetime.now().isoformat(timespec="seconds"),
        }
    meta["steps"]["tarama"] = tarama
    save_meta(run_id, meta)
    return run_id, sonuclar


def load_meta(run_id):
    with open(run_dir(run_id) / "meta.json", encoding="utf-8") as f:
        return json.load(f)


def save_meta(run_id, meta):
    with dosya.atomik(run_dir(run_id) / "meta.json") as f:
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
