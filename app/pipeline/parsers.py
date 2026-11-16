"""3. adım (1/2): ham çıktıları ortak formatta aday bulgulara dönüştürür.

Her aday şu alanları taşır:
    aday_id     kaynağa özgü tekil anahtar ("trivy:CVE-...:paket", "zap:10038", ...)
    kaynak      trivy | zap | challenges
    ad, cwe_id, cve_id, onem, kanit
    cvss_vector, cvss_score  (yalnızca Trivy'de dolu; diğerlerinde boş)
    kural       kurala göre ön seçime giriyor mu
    bayrak      dikkat edilmesi gereken durum (ör. önem derecesi ile CVSS çelişkisi)
"""

import json
import re

from pipeline.scans import RAW_FILES

# Challenge verisinde CWE yok; envanterde olmayan challenge'lar için kategoriye
# göre varsayılan CWE. Envanterdeki kayıtlar kendi (K2'nin verdiği) CWE'sini korur.
KATEGORI_CWE = {
    "Injection": "CWE-74",
    "XSS": "CWE-79",
    "Broken Access Control": "CWE-284",
    "Broken Authentication": "CWE-287",
    "Sensitive Data Exposure": "CWE-200",
    "XXE": "CWE-611",
    "Improper Input Validation": "CWE-20",
    "Security Misconfiguration": "CWE-16",
    "Unvalidated Redirects": "CWE-601",
    "Cryptographic Issues": "CWE-327",
    "Insecure Deserialization": "CWE-502",
    "Vulnerable Components": "CWE-1104",
    "Broken Anti Automation": "CWE-799",
    "Security through Obscurity": "CWE-656",
    "Observability Failures": "CWE-778",
}

ZAP_RISK = {3: "High", 2: "Medium", 1: "Low", 0: "Info"}
TRIVY_SIRA = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _oku(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _trivy_cvss(v):
    """Önce NVD, sonra GHSA, sonra herhangi bir kaynağın CVSS v3 değeri."""
    cvss = v.get("CVSS") or {}
    for kaynak in ["nvd", "ghsa", *cvss.keys()]:
        d = cvss.get(kaynak) or {}
        if d.get("V3Vector"):
            return d["V3Vector"], d.get("V3Score")
    return "", None


def parse_trivy(path):
    """Paket + zafiyet kimliği başına tek aday. Aynı paketin birden fazla
    sürümünde çıkan zafiyet tek satırda birleşir (envanterdeki V022 gibi)."""
    data = _oku(path)
    gruplar = {}
    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            key = (v["VulnerabilityID"], v["PkgName"])
            g = gruplar.setdefault(key, {"v": v, "surumler": []})
            if v.get("InstalledVersion") not in g["surumler"]:
                g["surumler"].append(v.get("InstalledVersion"))

    adaylar = []
    for (vid, pkg), g in gruplar.items():
        v = g["v"]
        surum = " / ".join(g["surumler"])
        vector, score = _trivy_cvss(v)
        onem = v.get("Severity", "UNKNOWN")
        bayrak = ""
        if score is not None and score >= 9.0 and onem in ("LOW", "MEDIUM"):
            bayrak = f"Trivy {onem} ama CVSS {score}"
        cwes = v.get("CweIDs") or []
        adaylar.append({
            "aday_id": f"trivy:{vid}:{pkg}",
            "kaynak": "trivy",
            "ad": f"{pkg} {surum} - {vid}",
            "cwe_id": cwes[0] if cwes else "",
            "cve_id": vid if vid.startswith("CVE-") else "",
            "onem": onem,
            "kanit": f"trivy.json: {pkg} {surum}; {vid}",
            "cvss_vector": vector,
            "cvss_score": score,
            "kural": onem in ("CRITICAL", "HIGH"),
            "bayrak": bayrak,
            "sira": TRIVY_SIRA.get(onem, 0),
            "aciklama": v.get("Title", ""),
        })
    return adaylar


def parse_zap(path):
    """Eklenti (plugin) başına tek aday. Aynı eklentinin varyantları birleşir;
    ör. COEP ve COOP başlık eksikliği (90004) tek satır olur (envanterdeki V021)."""
    data = _oku(path)
    gruplar = {}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            g = gruplar.setdefault(a["pluginid"], {"adlar": [], "risk": 0, "cwe": "", "urls": []})
            if a["name"] not in g["adlar"]:
                g["adlar"].append(a["name"])
            g["risk"] = max(g["risk"], int(a.get("riskcode", 0)))
            if not g["cwe"] and a.get("cweid", "-1") not in ("-1", "0", ""):
                g["cwe"] = f"CWE-{a['cweid']}"
            for inst in a.get("instances", []):
                if inst["uri"] not in g["urls"]:
                    g["urls"].append(inst["uri"])

    adaylar = []
    for pid, g in gruplar.items():
        urls = g["urls"]
        kanit = "; ".join(urls[:3]) + (f" (+{len(urls) - 3} adres)" if len(urls) > 3 else "")
        adaylar.append({
            "aday_id": f"zap:{pid}",
            "kaynak": "zap",
            "ad": " / ".join(g["adlar"]),
            "cwe_id": g["cwe"],
            "cve_id": "",
            "onem": ZAP_RISK[g["risk"]],
            "kanit": f"zap_baseline.json: {' / '.join(g['adlar'])}; {kanit}",
            "cvss_vector": "",
            "cvss_score": None,
            "kural": g["risk"] >= 2,
            "bayrak": "",
            "sira": g["risk"],
            "aciklama": "",
        })
    return adaylar


def parse_challenges(path):
    """Challenge başına tek aday. Önem bilgisi olmadığı için kural ön seçimi yok;
    zorluk (1-6 yıldız) bilgi olarak gösterilir."""
    data = _oku(path)
    items = data.get("data") if isinstance(data, dict) else data
    adaylar = []
    for c in items:
        aciklama = re.sub(r"<[^>]+>", "", c.get("description", ""))
        adaylar.append({
            "aday_id": f"challenges:{c['key']}",
            "kaynak": "challenges",
            "ad": c["name"],
            "cwe_id": KATEGORI_CWE.get(c.get("category"), ""),
            "cve_id": "",
            "onem": "★" * int(c.get("difficulty", 0)),
            "kanit": f"challenges.json: {c['name']} ({c.get('category')})",
            "cvss_vector": "",
            "cvss_score": None,
            "kural": False,
            "bayrak": "",
            "sira": int(c.get("difficulty", 0)),
            "aciklama": aciklama,
            "kategori": c.get("category", ""),
        })
    return adaylar


PARSERS = {"trivy": parse_trivy, "zap": parse_zap, "challenges": parse_challenges}


def adaylar(raw_dir):
    """Çalıştırmanın raw/ klasöründeki tüm kaynaklardan adayları üretir."""
    sonuc = []
    for kaynak, parser in PARSERS.items():
        path = raw_dir / RAW_FILES[kaynak]
        if path.exists():
            sonuc.extend(parser(path))
    return sonuc
