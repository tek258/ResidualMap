"""[S6][K3] Kontrol sonrası yollar: graph/paths_after.json

Her saldırı yolu için kontroller açıkken durumu ve riski (docs/olcum-metodolojisi.md, Bölüm 5.2-5.3):
    P_i (sonra)       = P_i × (1 − toplam_etkinlik_i)       (etkinlik: ai/residual_risk.csv)
    yol_riski (sonra) = Π P_i (sonra) × C_hedef
    status: yoldaki bir zafiyetin etkinliği ≥ 0.9 -> kesildi; > 0 -> zayifladi; yoksa acik

P_i ve C_hedef find_paths.py'den alınır (aynı formül, aynı hedef kritiklikleri); böylece
etkinliği 0 olan bir yolda path_risk_after == path_risk.

Kullanım (repo kökünden):
    python graph/paths_after.py
"""

import csv
import importlib.util
import json
import math
from collections import Counter
from pathlib import Path

KOK = Path(__file__).resolve().parents[1]
PATHS = KOK / "graph" / "paths.json"
RESIDUAL = KOK / "ai" / "residual_risk.csv"
INV = KOK / "inventory" / "inventory_v1.0.csv"
CIKTI = KOK / "graph" / "paths_after.json"
KESILDI_ESIK = 0.9


def _find_paths():
    spec = importlib.util.spec_from_file_location("find_paths", KOK / "graph" / "find_paths.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def durum(etkinlikler):
    if any(e >= KESILDI_ESIK for e in etkinlikler):
        return "kesildi"
    if any(e > 0 for e in etkinlikler):
        return "zayifladi"
    return "acik"


def main():
    fp = _find_paths()
    paths = json.loads(PATHS.read_text(encoding="utf-8"))
    with RESIDUAL.open(encoding="utf-8") as f:
        residual = {r["vuln_id"]: r for r in csv.DictReader(f)}
    with INV.open(encoding="utf-8") as f:
        olasilik = {r["vuln_id"]: fp.hesapla_cvss_probabilities(r["cvss_vector"]) for r in csv.DictReader(f)}

    sonuc = []
    for p in paths:
        zafiyetler = [n for n in p["path"] if n.startswith("V")]
        etk = {v: float(residual[v]["etkinlik"]) for v in zafiyetler}
        c = fp.TARGET_CRITICALITIES[p["target"]]
        once = sonra = None
        if all(olasilik.get(v) is not None for v in zafiyetler):
            once = round(math.prod(olasilik[v] for v in zafiyetler) * c, 4)
            sonra = round(math.prod(olasilik[v] * (1 - etk[v]) for v in zafiyetler) * c, 4)
        kesen = sorted({k.split(":")[0] for v in zafiyetler if etk[v] > 0
                        for k in residual[v]["kontroller"].split(", ") if ":" in k})
        sonuc.append({
            **p,
            "status": durum(etk.values()),
            "path_risk_after": sonra,
            "kontroller": kesen,
            "etkinlik": {v: round(e, 4) for v, e in etk.items()},
            "_kontrol": once,
        })

    # Tutarlılık: yeniden hesaplanan önceki risk find_paths.py'nin path_risk'iyle aynı olmalı
    for s in sonuc:
        if s["path_risk"] is not None and s["_kontrol"] is not None and abs(s["path_risk"] - s["_kontrol"]) > 1e-3:
            raise SystemExit(f"path_risk uyuşmuyor: {s['path']} {s['path_risk']} != {s['_kontrol']}")
        del s["_kontrol"]

    sonuc.sort(key=lambda s: (s["path_risk_after"] is not None, s["path_risk_after"] or 0,
                              s.get("secondary_v2_score", 0)), reverse=True)
    CIKTI.write_text(json.dumps(sonuc, indent=2, ensure_ascii=False), encoding="utf-8")

    say = Counter(s["status"] for s in sonuc)
    once_t = sum(s["path_risk"] or 0 for s in sonuc)
    sonra_t = sum(s["path_risk_after"] or 0 for s in sonuc)
    print(f"Yazıldı: {CIKTI.relative_to(KOK).as_posix()} ({len(sonuc)} yol)")
    print(f"Yol durumları: kesildi {say['kesildi']}, zayifladi {say['zayifladi']}, acik {say['acik']}")
    print(f"Toplam yol riski: {once_t:.2f} -> {sonra_t:.2f} (%{(once_t - sonra_t) / once_t * 100:.1f} düşüş)")
    print("Hedefe göre (kesildi/zayifladi/acik):")
    for hedef in sorted({s["target"] for s in sonuc}):
        c = Counter(s["status"] for s in sonuc if s["target"] == hedef)
        print(f"  {hedef}: {c['kesildi']}/{c['zayifladi']}/{c['acik']}")
    print("Kontroller sonrası en riskli 5 yol:")
    for s in sonuc[:5]:
        print(f"  {s['path_risk_after']:.2f} (önce {s['path_risk']:.2f}) {s['status']:9} {' -> '.join(s['path'])}")


if __name__ == "__main__":
    main()
