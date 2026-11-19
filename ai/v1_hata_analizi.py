"""[S3][K4] Model v1 hata analizi.

v1 sonuçlarını (ai/results_v1_llm.csv) uzman etiketleriyle (ai/expert_labels.csv)
yan yana koyar, uyuşmayan kayıtları ve gerekçe sorunlarını işaretler, özet
metrikleri yazdırır. Ollama gerektirmez; yalnızca mevcut CSV'leri okur.

Kullanım (repo kökünden):
    python ai/v1_hata_analizi.py

Çıktı:
    ai/v1_karsilastirma.csv   kayıt başına karşılaştırma ve hata işaretleri
"""

import csv
import os
import re

from scipy.stats import spearmanr

RESULTS = "results_v1_llm.csv"
EXPERT = "expert_labels.csv"
FEATURES = "features.csv"
OUT = "v1_karsilastirma.csv"

SIRA = {"Düşük": 1, "Orta": 2, "Yüksek": 3, "Kritik": 4}
SINIFLAR = ["Kritik", "Yüksek", "Orta", "Düşük"]


def skor_bandi(skor):
    """0-10 skoru uzman sınıflarına çevirir (CVSS v3.1 önem bantları)."""
    if skor >= 9.0:
        return "Kritik"
    if skor >= 7.0:
        return "Yüksek"
    if skor >= 4.0:
        return "Orta"
    return "Düşük"


def oku(yol, anahtar="vuln_id"):
    with open(yol, encoding="utf-8") as f:
        return {r[anahtar]: r for r in csv.DictReader(f)}


def gerekce_sorunlari(reason, feat):
    """Gerekçedeki sorunları kural tabanlı işaretler. Her işaret elle doğrulanmalı."""
    s = []
    r = reason or ""
    if re.search(r"Vuln ID:|CVSS Vektörü:|Bileşen \(Component\):|Notlar:|CVSS:3\.1/AV", r):
        s.append("girdiyi_tekrar")
    if re.search(r"end of the (document|instruction)|\{\s*$", r) or not r.strip().endswith((".", '"', ")")):
        s.append("yarim_kesik")
    kelimeler = re.findall(r"[A-Za-z]+", r.lower())
    ing = sum(k in {"the", "is", "and", "with", "of", "to", "for", "due", "here", "could"} for k in kelimeler)
    if kelimeler and ing / len(kelimeler) > 0.08:
        s.append("ingilizce")
    # Kayıtta CVE yokken CVE yazmak ya da yer tutucu (XXXX) kullanmak
    if "XXXX" in r or (not feat.get("cve_id") and re.search(r"CVE-\d{4}-\d+", r)):
        s.append("uydurma_cve")
    # Ölçüt metnini kopyalama: "yönetici yetkisi" admin ile ilgisi olmayan kayıtlarda
    admin_ilgili = re.search(r"admin|jsonwebtoken|express-jwt|parola|password|SQL", feat.get("name", ""), re.I)
    if re.search(r"yönetici yetkisi", r) and not admin_ilgili:
        s.append("olcut_kopyasi")
    if feat.get("epss_score") and "epss" not in r.lower():
        s.append("epss_yok_sayildi")
    return s


def main():
    res, exp, feat = oku(RESULTS), oku(EXPERT), oku(FEATURES)
    satirlar = []
    for vid in sorted(exp):
        f = feat.get(vid, {})
        cvss = float(f["cvss_score"]) if f.get("cvss_score") else None
        uzman = exp[vid]["label"]
        if vid not in res:
            satirlar.append({"vuln_id": vid, "uzman": uzman, "cvss": cvss, "durum": "atlandi"})
            continue
        r = res[vid]
        skor = float(r["risk_score_llm"])
        etiket = r["risk_label_llm"]
        fark = SIRA[etiket] - SIRA[uzman]
        satirlar.append({
            "vuln_id": vid,
            "kaynak": "bagimlilik" if f.get("cve_id") else "uygulama",
            "cvss": cvss,
            "epss": f.get("epss_score") or "",
            "uzman": uzman,
            "cvss_bandi": skor_bandi(cvss),
            "v1_skor": skor,
            "v1_etiket": etiket,
            "v1_skor_bandi": skor_bandi(skor),
            "durum": "uyumlu" if fark == 0 else ("fazla" if fark > 0 else "eksik"),
            "fark": fark,
            "skor_cvss_kopyasi": skor == cvss,
            "skor_etiket_celiskisi": skor_bandi(skor) != etiket,
            "gerekce_sorunlari": ";".join(gerekce_sorunlari(r["llm_reason"], f)),
            "gerekce_uzunlugu": len(r["llm_reason"]),
        })

    with open(OUT, "w", encoding="utf-8", newline="") as f:
        alanlar = list(satirlar[1].keys()) if len(satirlar) > 1 else list(satirlar[0].keys())
        w = csv.DictWriter(f, fieldnames=alanlar)
        w.writeheader()
        for s in satirlar:
            w.writerow({k: s.get(k, "") for k in alanlar})

    islenen = [s for s in satirlar if s["durum"] != "atlandi"]
    n = len(islenen)
    print(f"Kayıt: {len(satirlar)}, işlenen: {n}, atlanan: {[s['vuln_id'] for s in satirlar if s['durum']=='atlandi']}")

    print("\n== Uzman etiketiyle uyum (işlenen kayıtlar) ==")
    v1_uyum = sum(s["durum"] == "uyumlu" for s in islenen)
    bant_uyum = sum(s["cvss_bandi"] == s["uzman"] for s in islenen)
    bant_uyum36 = sum(skor_bandi(s["cvss"]) == s["uzman"] for s in satirlar)
    print(f"v1 etiketi            : {v1_uyum}/{n} ({100*v1_uyum/n:.1f}%)")
    print(f"CVSS bandı (baseline) : {bant_uyum}/{n} ({100*bant_uyum/n:.1f}%)   [36 kayıtta {bant_uyum36}/36]")
    yakin = sum(abs(s["fark"]) <= 1 for s in islenen)
    print(f"v1 en fazla 1 sınıf sapma: {yakin}/{n}")

    print("\n== Karışıklık matrisi (satır: uzman, sütun: v1) ==")
    print(f"{'':8}" + "".join(f"{c:>8}" for c in SINIFLAR))
    for u in SINIFLAR:
        print(f"{u:8}" + "".join(f"{sum(s['uzman']==u and s['v1_etiket']==c for s in islenen):>8}" for c in SINIFLAR))
    print("v1 etiket dağılımı:", {c: sum(s["v1_etiket"] == c for s in islenen) for c in SINIFLAR})
    print("uzman dağılımı    :", {c: sum(s["uzman"] == c for s in islenen) for c in SINIFLAR})

    print("\n== Sıralama: uzman etiketiyle Spearman ==")
    uz = [SIRA[s["uzman"]] for s in islenen]
    print(f"v1 skoru  : {spearmanr([s['v1_skor'] for s in islenen], uz)[0]:.3f}")
    print(f"v1 etiketi: {spearmanr([SIRA[s['v1_etiket']] for s in islenen], uz)[0]:.3f}")
    print(f"CVSS      : {spearmanr([s['cvss'] for s in islenen], uz)[0]:.3f}")

    print("\n== Skor davranışı ==")
    kopya = [s["vuln_id"] for s in islenen if s["skor_cvss_kopyasi"]]
    print(f"Skor = CVSS: {len(kopya)}/{n}; farklı olanlar: {[s['vuln_id'] for s in islenen if not s['skor_cvss_kopyasi']]}")
    print(f"Farklı skor sayısı: {len({s['v1_skor'] for s in islenen})}")
    celiski = [f"{s['vuln_id']}({s['v1_skor']}->{s['v1_etiket']})" for s in islenen if s["skor_etiket_celiskisi"]]
    print(f"Skor bandı ile kendi etiketi çelişen: {len(celiski)}: {', '.join(celiski)}")

    print("\n== Uyuşmayanlar ==")
    for s in islenen:
        if s["durum"] != "uyumlu":
            print(f"{s['vuln_id']} {s['kaynak']:10} CVSS {s['cvss']:>4}  uzman {s['uzman']:7} v1 {s['v1_etiket']:7} ({s['durum']})  {s['gerekce_sorunlari']}")

    print("\n== Kaynağa göre uyum ==")
    for k in ("uygulama", "bagimlilik"):
        g = [s for s in islenen if s["kaynak"] == k]
        print(f"{k:10}: {sum(s['durum']=='uyumlu' for s in g)}/{len(g)}")

    print("\n== Gerekçe sorunları ==")
    for etiket in ("girdiyi_tekrar", "yarim_kesik", "ingilizce", "uydurma_cve", "olcut_kopyasi", "epss_yok_sayildi"):
        ids = [s["vuln_id"] for s in islenen if etiket in s["gerekce_sorunlari"].split(";")]
        print(f"{etiket:17}: {len(ids):2}  {', '.join(ids)}")
    temiz = [s["vuln_id"] for s in islenen if not s["gerekce_sorunlari"]]
    print(f"{'sorunsuz':17}: {len(temiz):2}  {', '.join(temiz)}")
    print(f"\nYazıldı: {OUT}")


if __name__ == "__main__":
    os.makedirs("ai", exist_ok=True)
    main()
