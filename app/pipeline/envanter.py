"""3. adım (2/2): adayların dondurulmuş envanterle eşleştirilmesi ve seçilen
bulgulardan çalıştırmanın envanterinin (runs/<id>/inventory.csv) yazılması.

Envanterdeki bir kayda karşılık gelen aday seçildiğinde, envanterdeki satır
(K2'nin elle verdiği CVSS, yetkinlik, giriş noktası vb.) olduğu gibi kullanılır.
Envanterde olmayan adaylar için satır otomatik oluşturulur ve varsayılan
kullanılan alanlar işaretlenir.
"""

import csv
import re

from config import FROZEN_INVENTORY

# K2'nin ZAP bulgularını envantere alırken yaptığı eşleme kararları.
# Envanter ZAP eklenti kimliğini tutmadığı için burada açıkça yazılı.
# 90004 tek eklenti: COEP ve COOP başlıkları V021'de birleştirildi.
ZAP_ESLEME = {
    "V017": "10038",   # Content Security Policy (CSP) Header Not Set
    "V018": "10098",   # Cross-Domain Misconfiguration
    "V019": "10036",   # Server Leaks Version Information
    "V020": "10110",   # Dangerous JS Functions
    "V021": "90004",   # Cross-Origin-Embedder/Opener-Policy Header Missing
}

VARSAYILAN_SUTUNLAR = [
    "vuln_id", "cve_id", "name", "component", "cwe_id", "cvss_score", "cvss_vector",
    "epss_score", "exposure", "auth_required", "attack_complexity", "asset_criticality",
    "status", "notes", "requires_capability", "grants_capability", "entry_point",
    "entry_evidence",
]


def yukle_envanter(path=FROZEN_INVENTORY):
    if not path.exists():
        return VARSAYILAN_SUTUNLAR, []
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader.fieldnames), list(reader)


def satir_kaynagi(row):
    if row["cve_id"]:
        return "trivy"
    if row["entry_evidence"].startswith("zap_baseline.json"):
        return "zap"
    return "challenges"


def eslestir(adaylar, env_rows):
    """{vuln_id: aday_id ya da None}: envanterdeki her kayıt hangi adaya karşılık geliyor."""
    by_id = {a["aday_id"]: a for a in adaylar}
    challenge_adlari = {a["ad"].lower(): a["aday_id"] for a in adaylar if a["kaynak"] == "challenges"}
    sonuc = {}
    for r in env_rows:
        vid, kaynak, hit = r["vuln_id"], satir_kaynagi(r), None
        if kaynak == "trivy":
            hit = f"trivy:{r['cve_id']}:{r['component']}"
            if hit not in by_id:   # paket adı farklı yazılmışsa CVE'den bul
                hit = next((a["aday_id"] for a in adaylar
                            if a["kaynak"] == "trivy" and a["cve_id"] == r["cve_id"]), None)
        elif kaynak == "zap" and vid in ZAP_ESLEME:
            hit = f"zap:{ZAP_ESLEME[vid]}"
        elif kaynak == "challenges":
            m = re.match(r"challenges\.json:\s*([^;]+)", r["entry_evidence"])
            if m:
                hit = challenge_adlari.get(m.group(1).strip().lower())
        sonuc[vid] = hit if hit in by_id else None
    return sonuc


def karsilastir(adaylar, env_rows, eslesme):
    """Envanter ile bu çalıştırmanın verisi arasındaki fark."""
    eslesen = {a for a in eslesme.values() if a}
    mevcut_kaynaklar = {a["kaynak"] for a in adaylar}
    bulunamayan = [r for r in env_rows
                   if not eslesme.get(r["vuln_id"]) and satir_kaynagi(r) in mevcut_kaynaklar]
    yuklenmemis = [r for r in env_rows if satir_kaynagi(r) not in mevcut_kaynaklar]
    yeni = [a for a in adaylar if a["kural"] and a["aday_id"] not in eslesen]
    return {
        "bulunan": [r for r in env_rows if eslesme.get(r["vuln_id"])],
        "bulunamayan": bulunamayan,      # kaynağı yüklü ama bu taramada yok
        "yuklenmemis": yuklenmemis,      # kaynağı bu çalıştırmada hiç toplanmadı
        "yeni": yeni,                    # kurala uyuyor ama envanterde yok
    }


def _vektor_alanlari(vector):
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p) if vector else {}
    auth = "" if "PR" not in m else ("hayir" if m["PR"] == "N" else "evet")
    ac = "" if "AC" not in m else ("low" if m["AC"] == "L" else "high")
    return auth, ac


def yeni_satir(aday, vuln_id):
    """Envanterde olmayan bir aday için satır. İkinci değer, varsayılan
    kullanılan alanların listesi."""
    auth, ac = _vektor_alanlari(aday["cvss_vector"])
    varsayilan = ["asset_criticality", "exposure", "requires_capability",
                  "grants_capability", "entry_point"]
    if not aday["cvss_vector"]:
        varsayilan += ["cvss_score", "cvss_vector"]
    if aday["kaynak"] == "trivy":
        component = aday["ad"].split(" ")[0]
        entry = "dependency"
        varsayilan.remove("entry_point")          # Trivy için kural: her zaman dependency
        notes = f"[OTOMATIK] trivy.json: {aday['onem']}; {aday['aciklama']}"
    elif aday["kaynak"] == "zap":
        component, entry = "", "web"
        notes = f"[OTOMATIK] zap_baseline.json: {aday['onem']}"
    else:
        component, entry = aday.get("kategori", ""), "web"
        notes = f"[OTOMATIK] challenges.json: {aday.get('kategori', '')}; CWE kategoriden varsayıldı"
        varsayilan.append("cwe_id")
    if aday["bayrak"]:
        notes = f"[EMIN DEGIL] {notes}; {aday['bayrak']}"
    satir = {
        "vuln_id": vuln_id,
        "cve_id": aday["cve_id"],
        "name": aday["ad"],
        "component": component,
        "cwe_id": aday["cwe_id"],
        "cvss_score": "" if aday["cvss_score"] is None else str(aday["cvss_score"]),
        "cvss_vector": aday["cvss_vector"],
        "epss_score": "bilinmiyor",
        "exposure": "internet",
        "auth_required": auth,
        "attack_complexity": ac,
        "asset_criticality": "3",
        "status": "open",
        "notes": notes,
        "requires_capability": "none",
        "grants_capability": "none",
        "entry_point": entry,
        "entry_evidence": aday["kanit"],
    }
    return satir, varsayilan


def olustur(secili_ids, adaylar, env_rows, eslesme):
    """Seçili adaylardan envanter satırları. Envanterdeki kayıtlar korunur,
    yeniler envanterdeki en büyük numaradan sonra numaralanır."""
    aday_vid = {a: v for v, a in eslesme.items() if a}
    env_by_vid = {r["vuln_id"]: r for r in env_rows}
    son_no = max([int(v[1:]) for v in env_by_vid if re.fullmatch(r"V\d{3}", v)] or [0])

    korunan, yeniler, varsayilanlar = [], [], {}
    for a in adaylar:                      # aday sırası: kaynak, sonra önem
        if a["aday_id"] not in secili_ids:
            continue
        if a["aday_id"] in aday_vid:
            korunan.append(dict(env_by_vid[aday_vid[a["aday_id"]]]))
        else:
            son_no += 1
            satir, vars_ = yeni_satir(a, f"V{son_no:03d}")
            yeniler.append(satir)
            varsayilanlar[satir["vuln_id"]] = vars_
    korunan.sort(key=lambda r: r["vuln_id"])
    return korunan + yeniler, varsayilanlar


def kaydet(path, sutunlar, satirlar):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=sutunlar, extrasaction="ignore")
        w.writeheader()
        w.writerows(satirlar)
