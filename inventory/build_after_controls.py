"""[S6][K2] Kontrol sonrası envanter: inventory/after_controls.csv

Her zafiyetin kontroller açıkken durumunu, S5-K2'nin ham kanıtlarından
(inventory/raw/after_controls/) okuyarak belirler. Karar elle yazılmaz:
"engellendi" ya da "erisilebilir" demek için kanıt dosyasında ilgili satırın /
bulgunun bulunması gerekir. Kanıtı olmayan kayıt "test_edilmedi" olur ve
eşlemedeki beklenen etki yalnızca not sütununa yazılır.

Kullanım (repo kökünden):
    python inventory/build_after_controls.py

Girdiler:
    inventory/inventory_v1.0.csv, inventory/control_mapping.csv,
    inventory/raw/after_controls/{test-waf.log, test-iam.log, zap_baseline.json, trivy.json}
Çıktı:
    inventory/after_controls.csv
"""

import csv
import json
import re
from collections import Counter
from pathlib import Path

KOK = Path(__file__).resolve().parents[1]
INV = KOK / "inventory" / "inventory_v1.0.csv"
ESLEME = KOK / "inventory" / "control_mapping.csv"
HAM = KOK / "inventory" / "raw" / "after_controls"
CIKTI = KOK / "inventory" / "after_controls.csv"

KONTROLLER = ["waf", "sanal_yama", "ids", "iam", "segmentasyon", "yama"]
ETKISIZ = {"etkisiz", "kurulmadi", "uygulanmadi", ""}

# test-waf.log satırları -> zafiyet (etiket, beklenen engel kodu)
WAF_TESTLERI = {
    "V001": ["V001 SQLi (email alanı)"],
    "V002": ["SQLi"],
    "V003": ["V003 XSS (yol içinde iframe)", "V003 yolu NoSQLi (' || true || ')"],
    "V005": ["V005 XSS (description alanı)"],
}
# ZAP eklentisi -> zafiyet (envanter notlarıyla aynı eşleme)
ZAP_EKLENTI = {"V017": "10038", "V018": "10098", "V019": "10036", "V020": "10110", "V021": "90004"}


def _rel(p):
    return p.relative_to(KOK).as_posix()


def _json(p):
    return json.loads(p.read_text(encoding="utf-8-sig"))


def waf_sonuclari():
    """{etiket: http_kodu} test-waf.log'dan."""
    sonuc = {}
    for satir in (HAM / "test-waf.log").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^(?P<e>.*?)\s+-> HTTP (?P<k>\d{3})", satir)
        if m:
            sonuc[m["e"].strip()] = int(m["k"])
    return sonuc


def iam_sonuclari():
    """V009: girişsiz /ftp/ -> 302 Keycloak ve rolsüz misafir -> 403 test-iam.log'da OK mi?"""
    metin = (HAM / "test-iam.log").read_text(encoding="utf-8")
    girissiz = re.search(r"\[OK \] 302 .*?/ftp/ \(V009\)", metin) is not None
    misafir = re.search(r"\[OK \] 403 .*?misafir -> /ftp/", metin) is not None
    return girissiz and misafir


def zap_eklentileri():
    z = _json(HAM / "zap_baseline.json")
    return {a["pluginid"] for s in z.get("site", []) for a in s.get("alerts", [])}


def trivy_cveleri():
    t = _json(HAM / "trivy.json")
    return {v["VulnerabilityID"] for r in t.get("Results", []) for v in (r.get("Vulnerabilities") or [])}


def kaynak_turu(notes):
    n = re.sub(r"^\[EMIN DEGIL\]\s*", "", (notes or "").strip(), flags=re.I)
    if n.startswith("challenges.json"):
        return "Juice Shop challenge"
    if n.startswith("zap_baseline.json"):
        return "ZAP"
    if n.startswith("trivy.json"):
        return "Trivy"
    return "bilinmiyor"


def main():
    envanter = list(csv.DictReader(INV.open(encoding="utf-8")))
    esleme = {r["vuln_id"]: r for r in csv.DictReader(ESLEME.open(encoding="utf-8"))}
    waf, iam_ok = waf_sonuclari(), iam_sonuclari()
    zap, cve = zap_eklentileri(), trivy_cveleri()

    satirlar = []
    for inv in envanter:
        vid = inv["vuln_id"]
        e = esleme.get(vid, {})
        etkin = [f"{k}:{e[k].strip()}" for k in KONTROLLER if e.get(k, "").strip() not in ETKISIZ]
        kontrol = ", ".join(etkin) or "-"
        durum, dayanak, kanit, notu = None, e.get("dayanak", ""), "", ""

        if vid in WAF_TESTLERI:
            kodlar = [waf.get(et) for et in WAF_TESTLERI[vid]]
            if all(k == 403 for k in kodlar):
                azaltir = any(x.endswith(":azaltir") for x in etkin)
                durum = "azaltildi" if azaltir else "engellendi"
                dayanak, kanit = "test", _rel(HAM / "test-waf.log")
                notu = (f"test-waf.sh: {', '.join(WAF_TESTLERI[vid])} -> 403. "
                        + ("CRS 942100 tek kuralla tam eşikte (5 puan) yakalıyor; güvenlik payı yok."
                           if azaltir else ""))
            else:
                durum, dayanak, kanit = "erisilebilir", "test", _rel(HAM / "test-waf.log")
                notu = f"test-waf.sh beklenen 403'ü vermedi: {kodlar}"
        elif vid == "V009":
            if iam_ok:
                durum, dayanak, kanit = "engellendi", "test", _rel(HAM / "test-iam.log")
                notu = "test-iam.py: girişsiz /ftp/ ve atlatma denemeleri 302 (Keycloak), rolsüz misafir 403."
        elif vid in ZAP_EKLENTI:
            dayanak, kanit = "test", _rel(HAM / "zap_baseline.json")
            if ZAP_EKLENTI[vid] in zap:
                durum = "erisilebilir"
                notu = f"Kontroller sonrası ZAP taramasında eklenti {ZAP_EKLENTI[vid]} hâlâ var."
            else:
                durum = "engellendi"
                notu = f"Kontroller sonrası ZAP taramasında eklenti {ZAP_EKLENTI[vid]} yok (önce vardı)."
        elif inv.get("cve_id"):
            dayanak, kanit = "test", _rel(HAM / "trivy.json")
            if inv["cve_id"] in cve:
                durum = "erisilebilir"
                notu = (f"{inv['cve_id']} kontroller sonrası Trivy taramasında hâlâ var; yama uygulanmadı. "
                        "Paketin uygulamada erişilebilir kod yolu doğrulanmadı.")
            else:
                durum = "test_edilmedi"
                notu = f"{inv['cve_id']} kontroller sonrası Trivy taramasında yok; nedeni incelenmeli."

        if durum is None:
            durum, kanit = "test_edilmedi", ""
            beklenen = kontrol if etkin else "kontroller etkisiz"
            notu = f"Kontroller açıkken test edilmedi. Eşlemedeki beklenen etki: {beklenen} ({dayanak})."

        satirlar.append({"vuln_id": vid, "durum": durum, "kontrol": kontrol, "dayanak": dayanak,
                         "kanit_dosyasi": kanit, "not": notu.strip(),
                         "_kaynak": kaynak_turu(inv.get("notes"))})

    # Kabul kriteri: her engellendi satırının kanıt dosyası gerçekten var
    for s in satirlar:
        if s["durum"] == "engellendi" and not (KOK / s["kanit_dosyasi"]).is_file():
            raise SystemExit(f"{s['vuln_id']}: kanıt dosyası yok: {s['kanit_dosyasi']}")

    alanlar = ["vuln_id", "durum", "kontrol", "dayanak", "kanit_dosyasi", "not"]
    with CIKTI.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=alanlar, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(satirlar)

    print(f"Yazıldı: {_rel(CIKTI)} ({len(satirlar)} kayıt)")
    durumlar = ["engellendi", "azaltildi", "tespit_edildi", "erisilebilir", "test_edilmedi"]
    kaynaklar = ["Juice Shop challenge", "ZAP", "Trivy"]
    sayim = Counter((s["_kaynak"], s["durum"]) for s in satirlar)
    print("\n| Durum | " + " | ".join(kaynaklar) + " | Toplam |")
    print("|---|" + "---|" * (len(kaynaklar) + 1))
    for d in durumlar:
        hucre = [sayim[(k, d)] for k in kaynaklar]
        print(f"| {d} | " + " | ".join(map(str, hucre)) + f" | {sum(hucre)} |")
    toplam = [sum(sayim[(k, d)] for d in durumlar) for k in kaynaklar]
    print("| **Toplam** | " + " | ".join(map(str, toplam)) + f" | {sum(toplam)} |")


if __name__ == "__main__":
    main()
