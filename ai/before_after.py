"""[S6][K4] Önce/sonra tablosu, özet belgesi ve rapor grafiği.

Girdiler:
    ai/residual_risk.csv          (S5-K4: risk_before, risk_after, kontroller, dayanak)
    inventory/after_controls.csv  (S6-K2: durum)
    inventory/inventory_v1.0.csv  (ad ve kaynak türü)
Çıktılar:
    ai/before_after.csv
    docs/once-sonra-ozet.md
    report/img/once-sonra.png

Kullanım (repo kökünden):
    python ai/before_after.py
"""

import csv
import re
from pathlib import Path

KOK = Path(__file__).resolve().parents[1]
RESIDUAL = KOK / "ai" / "residual_risk.csv"
AFTER = KOK / "inventory" / "after_controls.csv"
INV = KOK / "inventory" / "inventory_v1.0.csv"
CIKTI_CSV = KOK / "ai" / "before_after.csv"
CIKTI_MD = KOK / "docs" / "once-sonra-ozet.md"
CIKTI_PNG = KOK / "report" / "img" / "once-sonra.png"

KAYNAKLAR = ["Juice Shop challenge", "ZAP", "Trivy"]
KAYNAK_ACIKLAMA = {
    "Juice Shop challenge": "uygulama zafiyeti (challenge ile doğrulanmış)",
    "ZAP": "web yapılandırma bulgusu (pasif tarama)",
    "Trivy": "kütüphane / işletim sistemi paketi",
}


def _oku(p):
    with p.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def kaynak_turu(notes):
    n = re.sub(r"^\[EMIN DEGIL\]\s*", "", (notes or "").strip(), flags=re.I)
    for onek, ad in (("challenges.json", "Juice Shop challenge"), ("zap_baseline.json", "ZAP"),
                     ("trivy.json", "Trivy")):
        if n.startswith(onek):
            return ad
    return "bilinmiyor"


def birlestir():
    residual = {r["vuln_id"]: r for r in _oku(RESIDUAL)}
    after = {r["vuln_id"]: r for r in _oku(AFTER)}
    inv = {r["vuln_id"]: r for r in _oku(INV)}
    eksik = {"residual_risk": sorted(set(inv) - set(residual)), "after_controls": sorted(set(inv) - set(after))}
    if any(eksik.values()):
        raise SystemExit(f"Eksik kayıtlar: {eksik}")

    satirlar = []
    for vid in sorted(inv):
        r, a = residual[vid], after[vid]
        once, sonra = float(r["risk_before"]), float(r["risk_after"])
        satirlar.append({
            "vuln_id": vid,
            "risk_before": round(once, 4),
            "risk_after": round(sonra, 4),
            "fark": round(once - sonra, 4),
            "kontrol": r["kontroller"],
            "durum": a["durum"],
            "dayanak": r["dayanak"],
            # yalnızca özet ve grafik için (CSV'ye yazılmaz)
            "_ad": inv[vid]["name"],
            "_kaynak": kaynak_turu(inv[vid].get("notes")),
            "_cwe": inv[vid].get("cwe_id", ""),
            "_not": a["not"],
        })
    return satirlar


def ozet(satirlar):
    def hesap(grup):
        once = sum(s["risk_before"] for s in grup)
        sonra = sum(s["risk_after"] for s in grup)
        n = len(grup)
        return {"n": n, "once": once, "sonra": sonra, "dusus": once - sonra,
                "yuzde": (once - sonra) / once * 100 if once else 0.0,
                "ort": (once - sonra) / n if n else 0.0}

    test = [s for s in satirlar if s["dayanak"] == "test"]
    return {
        "hepsi": hesap(satirlar),
        "test": hesap(test),
        "kaynak": {k: hesap([s for s in satirlar if s["_kaynak"] == k]) for k in KAYNAKLAR},
    }


def _aciklama(s):
    """Bir cümlelik açıklama: neden düştü ya da neden düşmedi."""
    d = s["durum"]
    if s["fark"] > 0:
        neden = {
            "engellendi": "kontroller açıkken saldırı isteği engelleniyor",
            "azaltildi": "saldırı isteği engelleniyor ama tam eşikte, güvenlik payı yok",
        }.get(d, "eşlemedeki beklenen etkiye göre azaldı, kontroller açıkken test edilmedi")
        return f"{s['kontrol']}: {neden}."
    if s["_kaynak"] == "Trivy":
        return "Kütüphane zafiyeti; hiçbir yama uygulanmadı ve ağ kontrolleri paketin içini görmez."
    if s["_kaynak"] == "ZAP":
        return "Eksik güvenlik başlığı ya da istemci tarafı bulgu; kontroller sonrası taramada hâlâ var."
    ozel = {
        "CWE-209": "Hata yanıtlarını WAF denetlemiyor; ayrıntılı hata mesajı sızmaya devam ediyor.",
        "CWE-798": "Kimlik bilgisi istemci tarafı koda gömülü; ağ kontrolleri dosyanın içeriğini değiştirmez.",
    }.get(s["_cwe"])
    return ozel or "Mantıksal / iş kuralı açığı; geçerli biçimdeki isteği WAF, IDS ve IAM ayırt edemiyor."


def ozet_md(satirlar, o):
    def satir(ad, h):
        return (f"| {ad} | {h['n']} | {h['once']:.2f} | {h['sonra']:.2f} | {h['dusus']:.2f} "
                f"| %{h['yuzde']:.1f} | {h['ort']:.2f} |")

    dusen = sorted([s for s in satirlar if s["fark"] > 0], key=lambda s: (-s["fark"], s["vuln_id"]))[:5]
    dusmeyen = [s for s in satirlar if s["fark"] == 0]
    durum_say = {d: sum(s["durum"] == d for s in satirlar)
                 for d in ["engellendi", "azaltildi", "tespit_edildi", "erisilebilir", "test_edilmedi"]}

    md = [
        "# Önce/sonra özeti (S6-K4)",
        "",
        "Kontroller (WAF, sanal yama, IDS, IAM, segmentasyon) devreye girdikten sonra artık riskin ne kadar düştüğü. "
        "Sayılar `ai/before_after.csv`'den `python ai/before_after.py` ile üretilir; risk tanımı "
        "`docs/olcum-metodolojisi.md`'de.",
        "",
        "- `risk_before`: model v2 skoru (`ai/results_v2_llm.csv`)",
        "- `risk_after = risk_before × (1 − toplam etkinlik)` (`ai/residual_risk.csv`)",
        "- `durum`: kontroller açıkken gözlenen sonuç (`inventory/after_controls.csv`)",
        "",
        "## 1. Toplam düşüş",
        "",
        "| Kapsam | Kayıt | Önce (Σ) | Sonra (Σ) | Düşüş | Düşüş % | Kayıt başına ort. |",
        "|---|---|---|---|---|---|---|",
        satir("Bütün kayıtlar", o["hepsi"]),
        satir("**Yalnızca test kanıtlı**", o["test"]),
        "",
        f"Güvenilir sayı ikinci satır: etkinliği test edilmiş eşlemelere dayanıyor. "
        f"`varsayim` dayanaklı {sum(s['dayanak'] == 'varsayim' for s in satirlar)} kayıt hesaba katılmadı "
        "(etkinlik 0, `risk_after = risk_before`).",
        "",
        "## 2. Kontroller açıkken durum",
        "",
        "| Durum | Kayıt |",
        "|---|---|",
        *[f"| {d} | {n} |" for d, n in durum_say.items()],
        "",
        "## 3. Kaynak türüne göre",
        "",
        "| Kaynak | Kayıt | Önce (Σ) | Sonra (Σ) | Düşüş | Düşüş % | Kayıt başına ort. |",
        "|---|---|---|---|---|---|---|",
        *[satir(f"{k}: {KAYNAK_ACIKLAMA[k]}", o["kaynak"][k]) for k in KAYNAKLAR],
        "",
        f"Kütüphane zafiyetlerinde düşüş %{o['kaynak']['Trivy']['yuzde']:.1f}: ağ kontrolleri paketlerin içini "
        "görmez ve hiçbir yama uygulanmadı. Toplam düşüşün "
        f"%{o['kaynak']['Juice Shop challenge']['dusus'] / o['hepsi']['dusus'] * 100:.0f}'i uygulama "
        "zafiyetlerinden, kalanı ZAP bulgularından (V019) geliyor.",
        "",
        "## 4. En çok düşen 5 kayıt",
        "",
        "| Kayıt | Ad | Önce | Sonra | Fark | Durum | Açıklama |",
        "|---|---|---|---|---|---|---|",
        *[f"| {s['vuln_id']} | {s['_ad']} | {s['risk_before']:.2f} | {s['risk_after']:.2f} | {s['fark']:.2f} "
          f"| {s['durum']} | {_aciklama(s)} |" for s in dusen],
        "",
        f"## 5. Hiç düşmeyen kayıtlar ({len(dusmeyen)})",
        "",
        "| Kayıt | Ad | Risk | Durum | Açıklama |",
        "|---|---|---|---|---|",
        *[f"| {s['vuln_id']} | {s['_ad']} | {s['risk_before']:.2f} | {s['durum']} | {_aciklama(s)} |"
          for s in sorted(dusmeyen, key=lambda s: (-s["risk_before"], s["vuln_id"]))],
        "",
        "## 6. Grafik",
        "",
        "![Önce/sonra](../report/img/once-sonra.png)",
        "",
    ]
    return "\n".join(md)


def grafik(satirlar):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    MAVI, TURUNCU = "#2a78d6", "#eb6834"          # kategorik sıra 1-2 (doğrulanmış çift)
    YUZEY, METIN, IKINCIL, IZGARA = "#fcfcfb", "#0b0b0b", "#52514e", "#e6e5e1"

    sirali = []
    for k in KAYNAKLAR:   # kaynak türüne göre bloklar, blok içinde önceki riske göre
        grup = sorted([s for s in satirlar if s["_kaynak"] == k], key=lambda s: (-s["risk_before"], s["vuln_id"]))
        sirali.append((k, grup))

    n = sum(len(g) for _, g in sirali) + (len(sirali) - 1)
    fig, ax = plt.subplots(figsize=(8, 0.28 * n + 1.6), dpi=200)
    fig.patch.set_facecolor(YUZEY)
    ax.set_facecolor(YUZEY)

    y, etiketler, konumlar, bloklar = 0, [], [], []
    for k, grup in sirali:
        bas = y
        for s in grup:
            ax.plot([s["risk_after"], s["risk_before"]], [y, y], color=IZGARA, lw=2, zorder=1,
                    solid_capstyle="round")
            ax.scatter(s["risk_before"], y, s=38, color=MAVI, zorder=3, edgecolor=YUZEY, linewidth=1.5)
            if s["fark"] > 0:
                ax.scatter(s["risk_after"], y, s=38, color=TURUNCU, zorder=4, edgecolor=YUZEY, linewidth=1.5)
            etiketler.append(f"{s['vuln_id']}  {s['durum'].replace('_', ' ')}")
            konumlar.append(y)
            y += 1
        bloklar.append((k, bas, y - 1))
        y += 1

    ax.set_yticks(konumlar, etiketler, fontsize=7, color=IKINCIL)
    ax.invert_yaxis()
    ax.set_xlim(0, 10)
    ax.set_xlabel("Risk (0–10)", fontsize=8, color=IKINCIL)
    ax.tick_params(axis="x", labelsize=7, colors=IKINCIL)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color=IZGARA, lw=0.6)
    ax.set_axisbelow(True)
    for kenar in ax.spines.values():
        kenar.set_visible(False)
    for k, bas, son in bloklar:
        ax.text(10.05, (bas + son) / 2, k, fontsize=7.5, color=METIN, va="center", ha="left", rotation=-90)
        if bas > 0:
            ax.axhline(bas - 1, color=IZGARA, lw=0.8)

    ax.scatter([], [], s=38, color=MAVI, label="Önce (model v2 skoru)")
    ax.scatter([], [], s=38, color=TURUNCU, label="Sonra (kontroller açık)")
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2, frameon=False, fontsize=8,
              labelcolor=METIN)
    ax.set_title("Kayıt başına artık risk: kontrollerden önce ve sonra", fontsize=10, color=METIN, pad=24,
                 loc="left")
    fig.text(0.01, 0.005, "Turuncu nokta yalnızca riski düşen kayıtlarda var; diğerlerinde önce = sonra.",
             fontsize=6.5, color=IKINCIL)
    fig.tight_layout()
    CIKTI_PNG.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(CIKTI_PNG, facecolor=YUZEY)
    plt.close(fig)


def main():
    satirlar = birlestir()
    alanlar = ["vuln_id", "risk_before", "risk_after", "fark", "kontrol", "durum", "dayanak"]
    with CIKTI_CSV.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=alanlar, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        w.writerows(satirlar)

    o = ozet(satirlar)
    CIKTI_MD.write_text(ozet_md(satirlar, o), encoding="utf-8")
    grafik(satirlar)

    h, t = o["hepsi"], o["test"]
    print(f"Yazıldı: {CIKTI_CSV.relative_to(KOK).as_posix()}, {CIKTI_MD.relative_to(KOK).as_posix()}, "
          f"{CIKTI_PNG.relative_to(KOK).as_posix()}")
    print(f"Bütün kayıtlar ({h['n']}): {h['once']:.2f} -> {h['sonra']:.2f} (%{h['yuzde']:.2f})")
    print(f"Yalnızca test ({t['n']}): {t['once']:.2f} -> {t['sonra']:.2f} (%{t['yuzde']:.2f})")
    for k in KAYNAKLAR:
        g = o["kaynak"][k]
        print(f"  {k}: {g['once']:.2f} -> {g['sonra']:.2f} (%{g['yuzde']:.2f})")


if __name__ == "__main__":
    main()
