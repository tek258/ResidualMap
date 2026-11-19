"""[S5][K4] Artık risk hesaplama ve duyarlılık analizi betiği.

Girdiler:
    - ai/results_v2_llm.csv (risk_score_llm -> risk_before)
    - inventory/control_mapping.csv

Çıktı:
    - ai/residual_risk.csv

Kullanım:
    python ai/residual_risk.py
    python ai/residual_risk.py --duyarlilik
"""

import argparse
import csv
import math
import os

ETKINLIK_SOZLUGU = {
    ("engeller", "test"): 0.90,
    ("engeller", "gerekce"): 0.63,
    ("azaltir", "test"): 0.50,
    ("azaltir", "gerekce"): 0.35,
    ("tespit_eder", "test"): 0.20,
    ("tespit_eder", "gerekce"): 0.14,
    ("etkisiz", "test"): 0.00,
    ("etkisiz", "gerekce"): 0.00,
}

KONTROL_SUTUNLARI = ["waf", "sanal_yama", "ids", "iam", "segmentasyon", "yama"]

SCORES_PATH = "ai/results_v2_llm.csv"
MAPPING_PATH = "inventory/control_mapping.csv"
OUTPUT_PATH = "ai/residual_risk.csv"


def normalize_etki(deger: str) -> str:
    """'tespit eder' gibi boşluklu ifadeleri standart anahtar biçimine çevirir."""
    return (deger or "").strip().lower().replace(" ", "_")


def tek_kontrol_etkinligi(etki: str, dayanak: str, sozluk: dict = None) -> float:
    """Tek bir kontrolün (etki, dayanak) çiftine göre etkinliğini döndürür."""
    tablo = sozluk if sozluk is not None else ETKINLIK_SOZLUGU
    etki_norm = normalize_etki(etki)
    dayanak_norm = (dayanak or "").strip().lower()

    if dayanak_norm == "varsayim" or etki_norm in ("", "etkisiz", "kurulmadi"):
        return 0.0

    return float(tablo.get((etki_norm, dayanak_norm), 0.0))


def toplam_etkinlik_hesapla(kontrol_etkileri: dict, dayanak: str, sozluk: dict = None) -> tuple[float, list[str], bool]:
    """Birden fazla kontrol için 1 - Π(1 - e_i) formülüyle toplam etkinliği hesaplar.

    Dönüş: (toplam_etkinlik, aktif_kontroller_listesi, hesaba_katildi_bayragi)
    """
    dayanak_norm = (dayanak or "").strip().lower()
    aktif_kontroller = []
    etkinlikler = []

    for kontrol_adi in KONTROL_SUTUNLARI:
        ham_etki = kontrol_etkileri.get(kontrol_adi, "")
        etki_norm = normalize_etki(ham_etki)
        if etki_norm not in ("", "etkisiz", "kurulmadi"):
            aktif_kontroller.append(f"{kontrol_adi}:{etki_norm}")
            if dayanak_norm != "varsayim":
                e = tek_kontrol_etkinligi(etki_norm, dayanak_norm, sozluk)
                if e > 0:
                    etkinlikler.append(e)

    if dayanak_norm == "varsayim":
        return 0.0, aktif_kontroller, False

    if not etkinlikler:
        return 0.0, aktif_kontroller, True

    kalan_carpan = math.prod(1.0 - e for e in etkinlikler)
    toplam = 1.0 - kalan_carpan
    return toplam, aktif_kontroller, True


def artik_risk_hesapla(risk_before: float, toplam_etkinlik: float) -> float:
    """risk_after = risk_before * (1 - toplam_etkinlik)"""
    return risk_before * (1.0 - toplam_etkinlik)


def veri_yukle(scores_path: str = SCORES_PATH, mapping_path: str = MAPPING_PATH) -> list[dict]:
    with open(scores_path, encoding="utf-8") as f:
        skorlar = {r["vuln_id"].strip(): float(r["risk_score_llm"]) for r in csv.DictReader(f)}

    with open(mapping_path, encoding="utf-8") as f:
        eslemeler = list(csv.DictReader(f))

    kayitlar = []
    for satir in eslemeler:
        vid = satir["vuln_id"].strip()
        if vid not in skorlar:
            raise KeyError(f"{vid} kaydı {scores_path} içinde bulunamadı.")
        kayitlar.append({
            "vuln_id": vid,
            "risk_before": skorlar[vid],
            "kontroller_dict": {k: satir.get(k, "") for k in KONTROL_SUTUNLARI},
            "dayanak": satir.get("dayanak", "").strip().lower(),
        })
    return kayitlar


def tablo_uret(kayitlar: list[dict], sozluk: dict = None) -> list[dict]:
    sonuclar = []
    for k in kayitlar:
        etkinlik, aktif_list, hesaba_katildi = toplam_etkinlik_hesapla(
            k["kontroller_dict"], k["dayanak"], sozluk
        )
        risk_after = artik_risk_hesapla(k["risk_before"], etkinlik)
        sonuclar.append({
            "vuln_id": k["vuln_id"],
            "risk_before": round(k["risk_before"], 4),
            "kontroller": ", ".join(aktif_list) if aktif_list else "yok",
            "etkinlik": round(etkinlik, 4),
            "risk_after": round(risk_after, 4),
            "dayanak": k["dayanak"],
            "hesaba_katildi": "Evet" if hesaba_katildi else "Hayır (varsayim)",
        })
    return sonuclar


def csv_yaz(satirlar: list[dict], output_path: str = OUTPUT_PATH) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    alanlar = ["vuln_id", "risk_before", "kontroller", "etkinlik", "risk_after", "dayanak", "hesaba_katildi"]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=alanlar)
        w.writeheader()
        w.writerows(satirlar)


def duyarlilik_analizi(kayitlar: list[dict]) -> None:
    """Metodoloji Bölüm 7: Etki değerleri ±0.1 ve gerekçe güven çarpanı 0.5 / 0.9 duyarlılığı."""
    def senaryo_olustur(etki_delta: float = 0.0, gerekce_carpan: float = 0.7) -> dict:
        baz_etki = {"engeller": 0.9, "azaltir": 0.5, "tespit_eder": 0.2, "etkisiz": 0.0}
        yeni = {}
        for etki, val in baz_etki.items():
            ayarli = 0.0 if etki == "etkisiz" else min(0.99, max(0.0, val + etki_delta))
            yeni[(etki, "test")] = round(ayarli * 1.0, 4)
            yeni[(etki, "gerekce")] = round(ayarli * gerekce_carpan, 4)
        return yeni

    senaryolar = [
        ("Baz senaryo (0.9 / 0.5 / 0.2, gerekçe=0.7)", ETKINLIK_SOZLUGU),
        ("Etki değerleri -0.1 (0.8 / 0.4 / 0.1)", senaryo_olustur(etki_delta=-0.1, gerekce_carpan=0.7)),
        ("Etki değerleri +0.1 (1.0->0.99 / 0.6 / 0.3)", senaryo_olustur(etki_delta=+0.1, gerekce_carpan=0.7)),
        ("Güven çarpanı gerekçe = 0.5", senaryo_olustur(etki_delta=0.0, gerekce_carpan=0.5)),
        ("Güven çarpanı gerekçe = 0.9", senaryo_olustur(etki_delta=0.0, gerekce_carpan=0.9)),
    ]

    baz_sonuc = tablo_uret(kayitlar, ETKINLIK_SOZLUGU)
    baz_top10 = [
        r["vuln_id"]
        for r in sorted(baz_sonuc, key=lambda x: (-x["risk_after"], x["vuln_id"]))[:10]
    ]

    print("\n== Duyarlılık Analizi (Metodoloji Bölüm 7) ==")
    print(f"Baz Top-10: {', '.join(baz_top10)}\n")
    for ad, sozluk in senaryolar:
        sonuc = tablo_uret(kayitlar, sozluk)
        top_before = sum(r["risk_before"] for r in sonuc)
        top_after = sum(r["risk_after"] for r in sonuc)
        dusus_yuzde = (top_before - top_after) / top_before * 100
        top10 = [
            r["vuln_id"]
            for r in sorted(sonuc, key=lambda x: (-x["risk_after"], x["vuln_id"]))[:10]
        ]
        farkli = len(set(top10) ^ set(baz_top10)) // 2
        sira_degisti = top10 != baz_top10
        print(f"- {ad}:")
        print(f"    Toplam risk düşüşü: %{dusus_yuzde:.2f} | Top-10 giren/çıkan: {farkli} | Sıra değişti mi: {'Evet' if sira_degisti else 'Hayır'}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--duyarlilik", action="store_true", help="Duyarlılık analizi tablosunu yazdır")
    args = ap.parse_args()

    kayitlar = veri_yukle()
    sonuclar = tablo_uret(kayitlar)
    csv_yaz(sonuclar)

    varsayim_sayisi = sum(1 for r in sonuclar if r["dayanak"] == "varsayim")
    top_before = sum(r["risk_before"] for r in sonuclar)
    top_after = sum(r["risk_after"] for r in sonuclar)
    print(f"Yazıldı: {OUTPUT_PATH} ({len(sonuclar)} kayıt, {varsayim_sayisi} varsayım hariç tutuldu)")
    print(f"Toplam risk: {top_before:.2f} -> {top_after:.2f} (Düşüş: %{(top_before - top_after) / top_before * 100:.2f})")

    if args.duyarlilik:
        duyarlilik_analizi(kayitlar)


if __name__ == "__main__":
    main()