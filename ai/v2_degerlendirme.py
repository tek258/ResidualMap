"""[S4][K4] baseline / v1 / v1-qwen / v2 karşılaştırma tablosu.

Bulunan sonuç dosyalarının hepsini aynı ölçülerle değerlendirir. Olmayan dosya
atlanır (ör. nocvss çalıştırılmadıysa). Few-shot kayıtları (V023, V006, V019)
ana tabloda değerlendirmeden çıkarılır; 36 kayıtlık tablo ayrıca yazdırılır.

Kullanım (repo kökünden):
    python ai/v2_degerlendirme.py

Çıktı:
    ai/v2_karsilastirma.csv   (ana tablo, few-shot hariç)
"""

import csv
import os

from scipy.stats import spearmanr

FEATURES = "ai/features.csv"
EXPERT = "ai/expert_labels.csv"
FEW_SHOT = {"V023", "V006", "V019"}
YONTEMLER = [
    ("v1 (phi3)", "ai/results_v1_llm.csv"),
    ("v1-qwen (kontrol)", "ai/results_v1_qwen_llm.csv"),
    ("v2", "ai/results_v2_llm.csv"),
    ("v2 (sayısal CVSS yok)", "ai/results_v2_nocvss_llm.csv"),
]
SIRA = {"Düşük": 1, "Orta": 2, "Yüksek": 3, "Kritik": 4}


def sinif(skor):
    if skor >= 9.0:
        return "Kritik"
    if skor >= 7.0:
        return "Yüksek"
    if skor >= 4.0:
        return "Orta"
    return "Düşük"


def oku(yol):
    with open(yol, encoding="utf-8") as f:
        return {r["vuln_id"]: r for r in csv.DictReader(f)}


def top10(skorlar):
    # Eşitlikte vuln_id sırası (baseline_ranking.py ile aynı)
    return {v for v, _ in sorted(skorlar.items(), key=lambda x: (-x[1], x[0]))[:10]}


def olc(ad, skorlar, cvss, uzman, kapsam):
    ids = [v for v in kapsam if v in skorlar]
    s = [skorlar[v] for v in ids]
    uz = [SIRA[uzman[v]] for v in ids]
    dogru = sum(sinif(skorlar[v]) == uzman[v] for v in ids)
    base_top = top10({v: cvss[v] for v in kapsam})
    return {
        "yontem": ad,
        "skorlanan": f"{len(ids)}/{len(kapsam)}",
        "farkli_skor": len(set(s)),
        "skor_eq_cvss": sum(skorlar[v] == cvss[v] for v in ids),
        "spearman": round(spearmanr(s, uz)[0], 3),
        "sinif_dogrulugu": f"{dogru}/{len(ids)} (%{100 * dogru / len(ids):.1f})",
        "top10_baseline": f"{len(top10({v: skorlar[v] for v in ids}) & base_top)}/10",
    }


def tablo(satirlar, baslik):
    print(f"\n== {baslik} ==")
    alanlar = list(satirlar[0].keys())
    gen = {a: max(len(a), *(len(str(r[a])) for r in satirlar)) for a in alanlar}
    print("  ".join(a.ljust(gen[a]) for a in alanlar))
    for r in satirlar:
        print("  ".join(str(r[a]).ljust(gen[a]) for a in alanlar))


def main():
    feat = oku(FEATURES)
    cvss = {v: float(r["cvss_score"]) for v, r in feat.items()}
    uzman = {v: r["label"] for v, r in oku(EXPERT).items()}
    tum = sorted(uzman)
    ana = [v for v in tum if v not in FEW_SHOT]

    sonuc = {"baseline (CVSS)": cvss}
    for ad, yol in YONTEMLER:
        if os.path.exists(yol):
            sonuc[ad] = {v: float(r["risk_score_llm"]) for v, r in oku(yol).items()}
            # Kimlik denetimi: yazım hatalı ya da eksik vuln_id sonuçları sessizce bozmasın
            bilinmeyen = sorted(set(sonuc[ad]) - set(uzman))
            eksik = sorted(set(uzman) - set(sonuc[ad]))
            if bilinmeyen or eksik:
                print(f"UYARI [{ad}] {yol}: bilinmeyen vuln_id {bilinmeyen or '-'}, eksik {eksik or '-'}")
        else:
            print(f"Atlandı (dosya yok): {yol}")

    ana_tablo = [olc(ad, s, cvss, uzman, ana) for ad, s in sonuc.items()]
    tablo(ana_tablo, f"Ana tablo: {len(ana)} kayıt (few-shot {', '.join(sorted(FEW_SHOT))} hariç)")
    tablo([olc(ad, s, cvss, uzman, tum) for ad, s in sonuc.items()], "36 kayıt (few-shot dahil, yalnızca bilgi için)")
    print("Not: sınıf doğruluğu skorun bandından hesaplanır. v1'in modelden gelen kendi etiketi "
          "ayrıca: 13/35 (docs/model-v1-hata-analizi.md).")

    print("\n== Sınıf dağılımı (ana tablo kayıtları) ==")
    print("uzman".ljust(24), {c: sum(uzman[v] == c for v in ana) for c in SIRA})
    for ad, s in sonuc.items():
        print(ad.ljust(24), {c: sum(sinif(s[v]) == c for v in ana if v in s) for c in SIRA})

    if "v2" in sonuc:
        v2 = oku("ai/results_v2_llm.csv")
        print("\n== v2: uzmandan ayrılan kayıtlar (ana tablo) ==")
        for v in ana:
            if v in v2 and v2[v]["risk_label_llm"] != uzman[v]:
                print(f"{v}  CVSS {cvss[v]:>4}  v2 {v2[v]['risk_score_llm']:>4} {v2[v]['risk_label_llm']:7} "
                      f"uzman {uzman[v]:7} | {v2[v]['llm_reason'][:110]}")
        std = [(v, r["score_std"], r["tekrar_skorlari"]) for v, r in v2.items() if r.get("score_std")]
        if std:
            print("\n== v2 tutarlılık ==")
            for v, s, t in std:
                print(f"{v}: skorlar {t}  std {s}")

    with open("ai/v2_karsilastirma.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(ana_tablo[0].keys()))
        w.writeheader()
        w.writerows(ana_tablo)
    print("\nYazıldı: ai/v2_karsilastirma.csv")


if __name__ == "__main__":
    main()
