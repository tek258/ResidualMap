"""Bu çalıştırmanın ham verisini referans taramayla (inventory/raw/, envanterin
dayandığı tarama) karşılaştırır: hangi bulgular kayboldu, hangileri yeni çıktı.

Envanterle karşılaştırmadan farkı: envanterde olmayan bulguları da kapsar.
ZAP bulgu türü düzeyinde (alert adı), Trivy paket + zafiyet düzeyinde,
challenge'lar challenge anahtarı düzeyinde karşılaştırılır.
"""

import hashlib
import json

from config import RAW_DIR
from pipeline.parsers import ZAP_RISK, parse_challenges, parse_trivy
from pipeline.scans import RAW_FILES


def _hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tarih(kaynak, path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    if kaynak == "zap":
        return data.get("created", data.get("@generated", ""))[:19]
    if kaynak == "trivy":
        return data.get("CreatedAt", "")[:19]
    return ""


def _zap_turleri(path):
    """{alert adı: {"onem", "pluginid", "ornek"}}"""
    data = json.loads(path.read_text(encoding="utf-8"))
    sonuc = {}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            sonuc[a["name"]] = {
                "onem": ZAP_RISK.get(int(a.get("riskcode", 0)), "?"),
                "pluginid": a["pluginid"],
                "ornek": len(a.get("instances", [])),
            }
    return sonuc


def _kayitlar(kaynak, path):
    """{anahtar: {"ad", "onem", "aday_id"}}: karşılaştırılacak birimler."""
    if kaynak == "zap":
        return {ad: {"ad": ad, "onem": v["onem"], "aday_id": f"zap:{v['pluginid']}",
                     "ornek": v["ornek"]}
                for ad, v in _zap_turleri(path).items()}
    parser = parse_trivy if kaynak == "trivy" else parse_challenges
    return {a["aday_id"]: {"ad": a["ad"], "onem": a["onem"], "aday_id": a["aday_id"]}
            for a in parser(path)}


def referans_farki(raw_dir):
    """Her kaynak için: durum ('ayni', 'farkli', 'referans_yok', 'toplanmadi'),
    tarihler, kaybolan ve yeni kayıtlar."""
    sonuc = {}
    for kaynak, dosya in RAW_FILES.items():
        bu, ref = raw_dir / dosya, RAW_DIR / dosya
        if not bu.exists():
            sonuc[kaynak] = {"durum": "toplanmadi"}
            continue
        if not ref.exists():
            sonuc[kaynak] = {"durum": "referans_yok"}
            continue
        if _hash(bu) == _hash(ref):
            sonuc[kaynak] = {"durum": "ayni"}
            continue
        a, b = _kayitlar(kaynak, ref), _kayitlar(kaynak, bu)
        sonuc[kaynak] = {
            "durum": "farkli",
            "ref_tarih": _tarih(kaynak, ref),
            "bu_tarih": _tarih(kaynak, bu),
            "ref_sayi": len(a),
            "bu_sayi": len(b),
            "kaybolan": [a[k] for k in a if k not in b],
            "yeni": [b[k] for k in b if k not in a],
        }
    return sonuc
