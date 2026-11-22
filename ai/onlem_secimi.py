"""Önlem seçimi ve uygulama öncesi senaryo hesabı

Soru: "Sınırlı eforla kritik varlıklara giden yolların riskini en çok azaltan önlem
bileşimi hangisi?" Önlemler henüz uygulanmadan, mevcut durumun (kontroller açık)
üzerine eklenerek hesaplanır.

Girdiler:
    inventory/onlem_katalogu.csv   aday önlemler (hedef zafiyetler, etki, efor, kesinti)
    ai/residual_risk.csv           mevcut durum: zafiyet başına risk_before ve etkinlik
    inventory/control_mapping.csv  doğrulama için (uygulanmış kontroller)
    graph/paths.json, inventory/inventory_v1.0.csv   yollar ve P_i (find_paths.py ile aynı)

Hesap (docs/olcum-metodolojisi.md ile aynı formüller):
    önlemin etkinliği  e = sözlük[(etki, güven)]    güven: gerekce (plan, varsayılan) ya da test
    birleşim           e' = 1 - (1 - e_mevcut)(1 - e_önlem)
    zafiyet riski      risk_before × (1 - e')
    yol riski          Π P_i (1 - e'_i) × C_hedef;  bir e'_i >= 0.9 ise yol "kesildi"
    seçim              bütçe (efor saati) içinde yol riskini en aza indiren alt küme:
                       aday sayısı küçük olduğu için bütün alt kümeler denenir (kesin sonuç);
                       karşılaştırma için açgözlü (risk düşüşü / saat) seçim de verilir.

Çıktılar:
    ai/onlem_tekil.csv         her önlem tek başına: risk düşüşü, kapanan yol, verim
    ai/onlem_secimi.json       bütçe -> en iyi bileşim (kesin ve açgözlü; kesintili/kesintisiz)
    docs/onlem-secimi.md       özet
    report/img/onlem-butce.png bütçe - kalan yol riski eğrisi

Kullanım (repo kökünden):
    python ai/onlem_secimi.py
    python ai/onlem_secimi.py --guven test      # önlemler uygulanıp test edilirse
    python ai/onlem_secimi.py --dogrula         # yalnızca doğrulama
"""

import argparse
import csv
import importlib.util
import itertools
import json
import math
import sys
from collections import Counter
from pathlib import Path

KOK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK / "ai"))
import residual_risk as rr  # noqa: E402

KATALOG = KOK / "inventory" / "onlem_katalogu.csv"
RESIDUAL = KOK / "ai" / "residual_risk.csv"
MAPPING = KOK / "inventory" / "control_mapping.csv"
PATHS = KOK / "graph" / "paths.json"
INV = KOK / "inventory" / "inventory_v1.0.csv"
CIKTI_TEKIL = KOK / "ai" / "onlem_tekil.csv"
CIKTI_SECIM = KOK / "ai" / "onlem_secimi.json"
CIKTI_BELGE = KOK / "docs" / "onlem-secimi.md"
CIKTI_PNG = KOK / "report" / "img" / "onlem-butce.png"
KESILDI_ESIK = 0.9
KESINTI_ADI = {"yok": "yok", "dusuk": "düşük", "var": "var"}
KONTROL_ADLARI = {"waf": "WAF ve nginx", "sanal_yama": "Sanal yamalar", "ids": "IDS (Suricata)",
                  "iam": "IAM (Keycloak)", "segmentasyon": "Segmentasyon", "yama": "Yama"}


def _find_paths():
    spec = importlib.util.spec_from_file_location("find_paths", KOK / "graph" / "find_paths.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _csv(yol):
    with open(yol, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


class Model:
    """Mevcut durum + yollar. Uygulama da bunu kullanır (bir kez yüklenir)."""

    def __init__(self):
        fp = _find_paths()
        res = {r["vuln_id"]: r for r in _csv(RESIDUAL)}
        self.risk_before = {v: float(r["risk_before"]) for v, r in res.items()}
        self.mevcut = {v: float(r["etkinlik"]) for v, r in res.items()}
        self.adlar = {r["vuln_id"]: r["name"] for r in _csv(INV)}
        olasilik = {r["vuln_id"]: fp.hesapla_cvss_probabilities(r["cvss_vector"]) for r in _csv(INV)}
        self.yollar = []
        for p in json.loads(PATHS.read_text(encoding="utf-8")):
            zaf = [n for n in p["path"] if n.startswith("V")]
            if any(olasilik.get(v) is None for v in zaf):
                continue
            self.yollar.append({"yol": p["path"], "hedef": p["target"], "zafiyetler": zaf,
                                "P": [olasilik[v] for v in zaf],
                                "C": fp.TARGET_CRITICALITIES[p["target"]]})
        self.katalog = []
        for r in _csv(KATALOG):
            self.katalog.append({**r, "hedefler": r["hedefler"].split(";"),
                                 "efor_saat": float(r["efor_saat"])})
        bilinmeyen = {v for o in self.katalog for v in o["hedefler"]} - set(self.risk_before)
        if bilinmeyen:
            raise SystemExit(f"Katalogda envanterde olmayan zafiyet: {sorted(bilinmeyen)}")

    # --- hesap ---
    def onlem_etkinligi(self, onlem, guven):
        e = rr.tek_kontrol_etkinligi(onlem["etki"], guven, vuln_id=onlem["onlem_id"], sutun="onlem")
        return {v: e for v in onlem["hedefler"]}

    @staticmethod
    def ekle(taban, ekler):
        """taban: {vid: e}; ekler: [{vid: e}, ...] -> birleşik etkinlik."""
        sonuc = dict(taban)
        for ek in ekler:
            for v, e in ek.items():
                sonuc[v] = 1 - (1 - sonuc.get(v, 0.0)) * (1 - e)
        return sonuc

    def degerlendir(self, etk):
        zaf = sum(rb * (1 - etk.get(v, 0.0)) for v, rb in self.risk_before.items())
        yol_t, durum, hedef = 0.0, Counter(), {}
        for y in self.yollar:
            e = [etk.get(v, 0.0) for v in y["zafiyetler"]]
            risk = math.prod(p * (1 - ei) for p, ei in zip(y["P"], e)) * y["C"]
            d = "kesildi" if any(x >= KESILDI_ESIK for x in e) else ("zayifladi" if any(x > 0 for x in e) else "acik")
            yol_t += risk
            durum[d] += 1
            h = hedef.setdefault(y["hedef"], {"risk": 0.0, "kesildi": 0, "zayifladi": 0, "acik": 0})
            h["risk"] += risk
            h[d] += 1
        return {"zafiyet_riski": zaf, "yol_riski": yol_t, "yol_durum": dict(durum), "hedef": hedef}

    def senaryo(self, onlem_idleri, guven="gerekce"):
        secili = [o for o in self.katalog if o["onlem_id"] in set(onlem_idleri)]
        etk = self.ekle(self.mevcut, [self.onlem_etkinligi(o, guven) for o in secili])
        s = self.degerlendir(etk)
        s["efor_saat"] = sum(o["efor_saat"] for o in secili)
        s["kesinti"] = sorted({o["kesinti"] for o in secili})
        s["etkinlik"] = etk
        return s

    # --- seçim ---
    def en_iyi(self, butce, guven="gerekce", kesintisiz=False):
        """Bütçe içinde yol riskini en aza indiren alt küme (bütün alt kümeler denenir)."""
        aday = [o for o in self.katalog if not (kesintisiz and o["kesinti"] == "var")]
        etkiler = {o["onlem_id"]: self.onlem_etkinligi(o, guven) for o in aday}
        en = None
        for k in range(len(aday) + 1):
            for alt in itertools.combinations(aday, k):
                efor = sum(o["efor_saat"] for o in alt)
                if efor > butce:
                    continue
                s = self.degerlendir(self.ekle(self.mevcut, [etkiler[o["onlem_id"]] for o in alt]))
                anahtar = (round(s["yol_riski"], 6), efor, round(s["zafiyet_riski"], 6))
                if en is None or anahtar < en[0]:
                    en = (anahtar, [o["onlem_id"] for o in alt], s, efor)
        _, idler, s, efor = en
        return {"butce": butce, "onlemler": idler, "efor_saat": efor,
                "yol_riski": s["yol_riski"], "zafiyet_riski": s["zafiyet_riski"], "yol_durum": s["yol_durum"]}

    def acgozlu(self, butce, guven="gerekce", kesintisiz=False):
        """Her adımda (yol riski düşüşü / saat) oranı en yüksek ve bütçeye sığan önlem."""
        kalan = [o for o in self.katalog if not (kesintisiz and o["kesinti"] == "var")]
        secili, etk, harcanan = [], dict(self.mevcut), 0.0
        simdi = self.degerlendir(etk)["yol_riski"]
        while True:
            en = None
            for o in kalan:
                if harcanan + o["efor_saat"] > butce:
                    continue
                yeni = self.degerlendir(self.ekle(etk, [self.onlem_etkinligi(o, guven)]))["yol_riski"]
                oran = (simdi - yeni) / o["efor_saat"]
                if oran > 1e-9 and (en is None or oran > en[0]):
                    en = (oran, o, yeni)
            if en is None:
                break
            _, o, simdi = en
            etk = self.ekle(etk, [self.onlem_etkinligi(o, guven)])
            secili.append(o["onlem_id"])
            harcanan += o["efor_saat"]
            kalan.remove(o)
        s = self.degerlendir(etk)
        return {"butce": butce, "onlemler": secili, "efor_saat": harcanan,
                "yol_riski": s["yol_riski"], "zafiyet_riski": s["zafiyet_riski"], "yol_durum": s["yol_durum"]}


def dogrula(m):
    """Uygulanmış kontrolleri (control_mapping.csv) önlem gibi sıfırdan ekleyip
    ai/residual_risk.csv'yi birebir üretmeli: motorun birleştirme mantığının kanıtı."""
    eslemeler = _csv(MAPPING)
    gruplar = []
    for sutun in rr.KONTROL_SUTUNLARI:
        grup = {}
        for r in eslemeler:
            if (r["dayanak"] or "").strip().lower() == "varsayim":
                continue
            e = rr.tek_kontrol_etkinligi(r[sutun], r["dayanak"], vuln_id=r["vuln_id"], sutun=sutun)
            if e > 0:
                grup[r["vuln_id"]] = e
        gruplar.append((sutun, grup))
    sifir = {v: 0.0 for v in m.risk_before}
    hesap = m.ekle(sifir, [g for _, g in gruplar])
    fark = {v: (hesap[v], m.mevcut[v]) for v in m.risk_before if abs(hesap[v] - m.mevcut[v]) > 1e-3}
    once = m.degerlendir(sifir)
    sonra = m.degerlendir(hesap)
    katki = []
    for sutun, g in gruplar:
        digerleri = [x for s, x in gruplar if s != sutun]
        olmadan = m.degerlendir(m.ekle(sifir, digerleri))
        katki.append((KONTROL_ADLARI[sutun], olmadan["yol_riski"] - sonra["yol_riski"],
                      olmadan["zafiyet_riski"] - sonra["zafiyet_riski"]))
    return fark, once, sonra, katki


def tekil_tablo(m, guven):
    taban = m.degerlendir(m.mevcut)
    satirlar = []
    for o in m.katalog:
        s = m.senaryo([o["onlem_id"]], guven)
        t = m.senaryo([o["onlem_id"]], "test")
        d_yol = taban["yol_riski"] - s["yol_riski"]
        satirlar.append({
            "onlem_id": o["onlem_id"], "ad": o["ad"], "tur": o["tur"], "hedefler": ";".join(o["hedefler"]),
            "efor_saat": o["efor_saat"], "kesinti": o["kesinti"],
            "yol_riski_dususu": round(d_yol, 4),
            "zafiyet_riski_dususu": round(taban["zafiyet_riski"] - s["zafiyet_riski"], 4),
            "verim_saat_basina": round(d_yol / o["efor_saat"], 4),
            "kapanan_yol_test_edilirse": t["yol_durum"].get("kesildi", 0) - taban["yol_durum"].get("kesildi", 0),
        })
    satirlar.sort(key=lambda r: -r["verim_saat_basina"])
    return taban, satirlar


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--guven", choices=["gerekce", "test"], default="gerekce",
                    help="önlemlerin etkinlik dayanağı: gerekce (plan aşaması) ya da test")
    ap.add_argument("--dogrula", action="store_true", help="yalnızca doğrulama")
    args = ap.parse_args()
    m = Model()

    fark, once, sonra, katki = dogrula(m)
    print(f"Doğrulama: uygulanmış kontroller sıfırdan eklendi -> zafiyet riski "
          f"{once['zafiyet_riski']:.2f} -> {sonra['zafiyet_riski']:.2f}, yol riski "
          f"{once['yol_riski']:.2f} -> {sonra['yol_riski']:.2f}, kesilen yol {sonra['yol_durum'].get('kesildi', 0)}")
    if fark:
        raise SystemExit(f"Doğrulama başarısız, residual_risk.csv ile farklı: {fark}")
    print("Doğrulama: residual_risk.csv ile birebir aynı.")
    if args.dogrula:
        return

    taban, tekil = tekil_tablo(m, args.guven)
    with open(CIKTI_TEKIL, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(tekil[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(tekil)

    toplam_efor = sum(o["efor_saat"] for o in m.katalog)
    butceler = list(range(0, int(math.ceil(toplam_efor)) + 1))
    sonuc = {"guven": args.guven, "taban": {k: taban[k] for k in ("zafiyet_riski", "yol_riski", "yol_durum")},
             "toplam_efor": toplam_efor, "egri": {}}
    for ad, kesintisiz in (("tum", False), ("kesintisiz", True)):
        sonuc["egri"][ad] = {"kesin": [m.en_iyi(b, args.guven, kesintisiz) for b in butceler],
                             "acgozlu": [m.acgozlu(b, args.guven, kesintisiz) for b in butceler]}
    CIKTI_SECIM.write_text(json.dumps(sonuc, indent=1, ensure_ascii=False), encoding="utf-8")

    belge_ve_grafik(m, taban, tekil, sonuc, once, sonra, katki, args.guven)
    for yol in (CIKTI_TEKIL, CIKTI_SECIM, CIKTI_BELGE, CIKTI_PNG):
        print("Yazıldı:", yol.relative_to(KOK).as_posix())
    for b in (8, 16, 24):
        s = next(x for x in sonuc["egri"]["tum"]["kesin"] if x["butce"] == b)
        print(f"Bütçe {b} saat: {', '.join(s['onlemler'])} -> yol riski {taban['yol_riski']:.2f} -> "
              f"{s['yol_riski']:.2f} (%{(1 - s['yol_riski'] / taban['yol_riski']) * 100:.1f})")


def belge_ve_grafik(m, taban, tekil, sonuc, once, sonra, katki, guven):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    kes = sonuc["egri"]["tum"]["kesin"]
    kesz = sonuc["egri"]["kesintisiz"]["kesin"]
    acg = sonuc["egri"]["tum"]["acgozlu"]
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=200)
    ax.step([s["butce"] for s in kes], [s["yol_riski"] for s in kes], where="post", lw=2,
            color="#2a6fdb", label="En iyi bileşim")
    ax.step([s["butce"] for s in kesz], [s["yol_riski"] for s in kesz], where="post", lw=2,
            color="#e8743b", label="En iyi bileşim, kesinti gerektirmeyen")
    ax.step([s["butce"] for s in acg], [s["yol_riski"] for s in acg], where="post", lw=1.2,
            ls="--", color="#666", label="Açgözlü (risk düşüşü / saat)")
    ax.set_xlabel("Efor bütçesi (saat)")
    ax.set_ylabel("Kalan toplam yol riski")
    ax.set_title("Bütçeye göre kalan yol riski (mevcut kontrollerin üzerine)", loc="left", fontsize=11)
    ax.grid(alpha=.3)
    ax.set_ylim(bottom=0)
    ax.legend(frameon=False, fontsize=8)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    fig.tight_layout()
    fig.savefig(CIKTI_PNG)
    plt.close(fig)

    ad = {o["onlem_id"]: o["ad"] for o in m.katalog}
    ty = taban["yol_riski"]
    satir = [
        "# Önlem seçimi ve uygulama öncesi senaryo",
        "",
        "Soru: *sınırlı eforla kritik varlıklara giden yolların riskini en çok azaltan önlem bileşimi hangisi?* "
        "Aday önlemler henüz uygulanmadı; mevcut durumun (WAF, sanal yamalar, IDS, IAM, segmentasyon açık) "
        "üzerine eklenerek hesaplandı. Belge `python ai/onlem_secimi.py` ile üretilir.",
        "",
        f"- Aday önlemler: `inventory/onlem_katalogu.csv` ({len(m.katalog)} önlem, toplam {sonuc['toplam_efor']:.0f} saat). "
        "Efor ve kesinti değerleri ekip tahminidir; gerekçesi katalogda.",
        f"- Önlem etkinliği metodoloji sözlüğünden: henüz uygulanmadığı için dayanak **{guven}** "
        f"(`engeller` = {rr.ETKINLIK_SOZLUGU[('engeller', guven)]}). Uygulanıp test edilince 0.9 olur.",
        "- Mevcut etkinlikle birleşim: `1 − (1 − e_mevcut)(1 − e_önlem)`. Yol riski: `Π P_i(1 − e_i) × C_hedef` "
        "(metodoloji 5.2, `paths_after.py` ile aynı).",
        "- Amaç: toplam yol riskini en aza indirmek (kritik varlık ağırlıklı). Aday sayısı küçük olduğu için "
        "bütçeye sığan **bütün alt kümeler** denendi; sonuç kesin en iyidir. Açgözlü seçim karşılaştırma için.",
        "",
        "## 1. Doğrulama",
        "",
        "Uygulanmış kontroller (`control_mapping.csv`) aynı motorla sıfırdan eklendiğinde `ai/residual_risk.csv` "
        "36 kayıtta birebir üretiliyor:",
        "",
        "| | Kontrolsüz | Kontroller açık |",
        "|---|---|---|",
        f"| Zafiyet riski (Σ) | {once['zafiyet_riski']:.2f} | {sonra['zafiyet_riski']:.2f} |",
        f"| Yol riski (Σ) | {once['yol_riski']:.2f} | {sonra['yol_riski']:.2f} |",
        f"| Kesilen yol | {once['yol_durum'].get('kesildi', 0)} | {sonra['yol_durum'].get('kesildi', 0)} |",
        "",
        "Uygulanmış kontrollerin katkısı (o kontrol olmasaydı yol riski ne kadar yüksek olurdu):",
        "",
        "| Kontrol | Yol riski katkısı | Zafiyet riski katkısı |",
        "|---|---|---|",
        *[f"| {k} | {y:.2f} | {z:.2f} |" for k, y, z in sorted(katki, key=lambda x: -x[1]) if y > 1e-6 or z > 1e-6],
        "",
        "## 2. Önlemler tek başına",
        "",
        f"Mevcut durum: yol riski {ty:.2f}, zafiyet riski {taban['zafiyet_riski']:.2f}, "
        f"yollar {taban['yol_durum'].get('kesildi', 0)} kesildi / {taban['yol_durum'].get('zayifladi', 0)} zayıfladı / "
        f"{taban['yol_durum'].get('acik', 0)} açık. Sıralama: saat başına yol riski düşüşü.",
        "",
        "| Önlem | Hedef | Efor (sa) | Kesinti | Yol riski düşüşü | Saat başına | Test edilirse kapanan yol |",
        "|---|---|---|---|---|---|---|",
        *[f"| {r['onlem_id']} {r['ad']} | {r['hedefler'].replace(';', ', ')} | {r['efor_saat']:.0f} | {KESINTI_ADI[r['kesinti']]} | "
          f"{r['yol_riski_dususu']:.2f} | {r['verim_saat_basina']:.2f} | {r['kapanan_yol_test_edilirse']} |" for r in tekil],
        "",
        "## 3. Bütçeye göre en iyi bileşim",
        "",
        "![Bütçe - kalan yol riski](../report/img/onlem-butce.png)",
        "",
        "| Bütçe (sa) | En iyi bileşim | Efor | Kalan yol riski | Düşüş | Kesintisiz en iyi | Kalan |",
        "|---|---|---|---|---|---|---|",
    ]
    for b in (2, 4, 8, 12, 16, 24, 32, int(sonuc["toplam_efor"])):
        if b > sonuc["toplam_efor"]:
            continue
        s = next(x for x in kes if x["butce"] == b)
        z = next(x for x in kesz if x["butce"] == b)
        satir.append(f"| {b} | {', '.join(s['onlemler']) or '-'} | {s['efor_saat']:.0f} | {s['yol_riski']:.2f} | "
                     f"%{(1 - s['yol_riski'] / ty) * 100:.1f} | {', '.join(z['onlemler']) or '-'} | {z['yol_riski']:.2f} |")
    fark = [(a["butce"], a["yol_riski"] - k["yol_riski"]) for a, k in zip(acg, kes) if a["yol_riski"] - k["yol_riski"] > 1e-6]
    son = kes[-1]
    satir += [
        "",
        f"Bütün önlemler ({son['efor_saat']:.0f} saat): yol riski {ty:.2f} -> {son['yol_riski']:.2f} "
        f"(%{(1 - son['yol_riski'] / ty) * 100:.1f}), zafiyet riski {taban['zafiyet_riski']:.2f} -> {son['zafiyet_riski']:.2f}.",
        "",
        ("Açgözlü seçim " + (f"{len(fark)} bütçede kesin sonuçtan kötü (en fazla {max(f for _, f in fark):.2f} yol riski fazla); "
                             "bu yüzden sonuç kesin aramayla veriliyor." if fark else "bütün bütçelerde kesin sonuçla aynı.")),
        "",
        "Önlem adları: " + "; ".join(f"{k} {v}" for k, v in ad.items()) + ".",
        "",
        "## 4. Sınırlılıklar",
        "",
        "- Efor ve kesinti değerleri tahmindir; bakım penceresi ve ekip kapasitesi gibi kısıtlar yalnızca toplam saat "
        "ve \"kesinti gerektirmeyen\" seçeneğiyle temsil ediliyor.",
        "- Önlemlerin etkisi uygulanmadan önce `gerekce` dayanağıyla (temkinli) hesaplanıyor; uygulanıp test edilince "
        "`control_mapping.csv`'ye `test` olarak girer ve sonuçlar yeniden üretilir.",
        "- Juice Shop kasıtlı olarak açıklı bir uygulama: yamalar ve kod düzeltmeleri gerçek lab'da challenge'ları kapatır. "
        "Bu bölüm bir planlama senaryosudur, lab'a uygulanmadı.",
        "- Saldırı grafiği zafiyet zincirlerini (ön koşul/kazanım) içeriyor, ama bir adımın birden fazla koşulu birlikte "
        "gerektirdiği durumlar (VE düğümleri) modellenmiyor.",
        "",
    ]
    CIKTI_BELGE.write_text("\n".join(satir), encoding="utf-8")


if __name__ == "__main__":
    main()
