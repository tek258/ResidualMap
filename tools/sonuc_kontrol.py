"""[S6][K1] Sonuç dosyalarının kontrolü ve docs/sonuc-dosyalari.md

Dondurmadan (v-sonuclar etiketi) önce çalıştırılır:
  1. Her sonuç dosyası var mı, 36 kaydın hepsi her tabloda var mı?
  2. Çıktılar birbiriyle tutarlı mı? (durumlar, kesilen yollar, risk değerleri)
  3. docs/sonuc-dosyalari.md: dosya, üreten script, komut, kayıt sayısı, SHA-256

SHA-256, satır sonları LF'ye çevrilerek hesaplanır (metin dosyaları için). Böylece
Windows'ta (git autocrlf) ve Linux'ta alınan klonlar aynı özeti verir.

Kullanım (repo kökünden):
    python tools/sonuc_kontrol.py            # kontrol + belge
    python tools/sonuc_kontrol.py --sadece-kontrol
Çıkış kodu: tutarsızlık varsa 1.
"""

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

KOK = Path(__file__).resolve().parents[1]
BELGE = KOK / "docs" / "sonuc-dosyalari.md"

# (dosya, üreten, komut, açıklama)
DOSYALAR = [
    ("inventory/inventory_v1.0.csv", "K2 (elle, S1)", "-", "Dondurulmuş envanter"),
    ("inventory/control_mapping.csv", "K2 (elle, S4-S5)", "-", "Kontrol eşlemesi (etki, dayanak, kanıt)"),
    ("inventory/after_controls.csv", "inventory/build_after_controls.py", "python inventory/build_after_controls.py",
     "Kontroller açıkken durum"),
    ("ai/results_v2_llm.csv", "ai/model_v2_local_llm.py", "python ai/model_v2_local_llm.py --tekrar-ids V001 V012 V035",
     "AI risk skoru (risk_before)"),
    ("ai/residual_risk.csv", "ai/residual_risk.py", "python ai/residual_risk.py", "Zafiyet düzeyinde artık risk"),
    ("ai/before_after.csv", "ai/before_after.py", "python ai/before_after.py", "Önce/sonra tablosu"),
    ("graph/edges.json", "graph/generate_edges.py", "python graph/generate_edges.py", "Saldırı grafiği kenarları"),
    ("graph/paths.json", "graph/find_paths.py", "python graph/find_paths.py", "Saldırı yolları ve riskleri"),
    ("graph/edges_after.json", "graph/cut_edges.py", "python graph/cut_edges.py", "Kontrol sonrası kenar durumları"),
    ("graph/paths_after.json", "graph/paths_after.py", "python graph/paths_after.py",
     "Kontrol sonrası yol durumu ve riski"),
    ("docs/once-sonra-ozet.md", "ai/before_after.py", "python ai/before_after.py", "Önce/sonra özeti"),
    ("report/img/once-sonra.png", "ai/before_after.py", "python ai/before_after.py", "Rapor grafiği"),
    ("graph/attack_graph_v2.html", "graph/visualize_graph.py", "python graph/visualize_graph.py", "Grafik (önce)"),
    ("graph/attack_graph_after.html", "graph/visualize_graph.py", "python graph/visualize_graph.py --after",
     "Grafik (sonra)"),
    ("report/img/graf-once.png", "tarayıcı ekran görüntüsü", "attack_graph_v2.html, 1600×1000, ölçek 2",
     "Rapor görseli"),
    ("report/img/graf-sonra.png", "tarayıcı ekran görüntüsü", "attack_graph_after.html, 1600×1000, ölçek 2",
     "Rapor görseli"),
    ("inventory/onlem_katalogu.csv", "elle (ek savunma)", "-", "Aday önlemler: etki, efor, kesinti, gerekçe"),
    ("ai/onlem_tekil.csv", "ai/onlem_secimi.py", "python ai/onlem_secimi.py", "Önlemler tek başına"),
    ("ai/onlem_secimi.json", "ai/onlem_secimi.py", "python ai/onlem_secimi.py", "Bütçeye göre en iyi bileşim"),
    ("docs/onlem-secimi.md", "ai/onlem_secimi.py", "python ai/onlem_secimi.py", "Önlem seçimi özeti"),
    ("report/img/onlem-butce.png", "ai/onlem_secimi.py", "python ai/onlem_secimi.py", "Rapor grafiği"),
]
METIN = {".csv", ".json", ".md", ".html", ".py", ".txt"}

hatalar, notlar = [], []


def sha256(p):
    veri = p.read_bytes()
    if p.suffix in METIN:
        veri = veri.replace(b"\r\n", b"\n")
    return hashlib.sha256(veri).hexdigest()


def csv_oku(yol):
    with (KOK / yol).open(encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def json_oku(yol):
    return json.loads((KOK / yol).read_text(encoding="utf-8-sig"))


def kontrol(kosul, mesaj):
    if not kosul:
        hatalar.append(mesaj)
    return kosul


def zafiyet_kontrolleri():
    inv = {r["vuln_id"] for r in csv_oku("inventory/inventory_v1.0.csv")}
    kontrol(len(inv) == 36, f"envanterde {len(inv)} kayıt (36 bekleniyor)")
    for yol in ["inventory/control_mapping.csv", "inventory/after_controls.csv", "ai/results_v2_llm.csv",
                "ai/residual_risk.csv", "ai/before_after.csv"]:
        ids = [r["vuln_id"] for r in csv_oku(yol)]
        kontrol(len(ids) == len(set(ids)), f"{yol}: tekrar eden vuln_id")
        kontrol(set(ids) == inv, f"{yol}: eksik {sorted(inv - set(ids))}, fazla {sorted(set(ids) - inv)}")

    for yol in ["graph/edges.json", "graph/edges_after.json"]:
        dugum = {n for e in json_oku(yol) for n in (e["source"], e["target"]) if n.startswith("V")}
        kontrol(dugum == inv, f"{yol}: grafikte olmayan zafiyetler {sorted(inv - dugum)}")
    for yol in ["graph/paths.json", "graph/paths_after.json"]:
        dugum = {n for p in json_oku(yol) for n in p["path"] if n.startswith("V")}
        kontrol(dugum == inv, f"{yol}: hiçbir yolda olmayan zafiyetler {sorted(inv - dugum)}")
    return inv


def tutarlilik_kontrolleri():
    after = {r["vuln_id"]: r for r in csv_oku("inventory/after_controls.csv")}
    residual = {r["vuln_id"]: r for r in csv_oku("ai/residual_risk.csv")}
    ba = {r["vuln_id"]: r for r in csv_oku("ai/before_after.csv")}
    edges_after = json_oku("graph/edges_after.json")
    paths, paths_after = json_oku("graph/paths.json"), json_oku("graph/paths_after.json")

    # before_after, kaynaklarıyla aynı mı?
    for v, r in ba.items():
        kontrol(abs(float(r["risk_after"]) - float(residual[v]["risk_after"])) < 1e-6,
                f"{v}: before_after.risk_after != residual_risk.risk_after")
        kontrol(r["durum"] == after[v]["durum"], f"{v}: before_after.durum != after_controls.durum")

    # Kesilen zafiyetler: kenarlarda "kesildi" olanlar = after_controls'ta "engellendi" olanlar
    kenar_durum = {}
    for e in edges_after:
        v = e["target"] if e["source"].startswith("node_entry_") else e["source"]
        if v.startswith("V"):
            kenar_durum.setdefault(v, set()).add(e["status"])
    kesilen = {v for v, s in kenar_durum.items() if "kesildi" in s}
    engellendi = {v for v, r in after.items() if r["durum"] == "engellendi"}
    kontrol(kesilen == engellendi,
            f"edges_after 'kesildi' {sorted(kesilen)} != after_controls 'engellendi' {sorted(engellendi)}")
    azaltildi = {v for v, r in after.items() if r["durum"] == "azaltildi"}
    zayif = {v for v, s in kenar_durum.items() if "zayifladi" in s}
    kontrol(azaltildi <= zayif, f"'azaltildi' kayıtlar kenarlarda zayıflamamış: {sorted(azaltildi - zayif)}")

    # Yollar: paths_after, paths ile aynı yolları içeriyor ve durum sayıları edges_after ile uyuşuyor
    kontrol({tuple(p["path"]) for p in paths} == {tuple(p["path"]) for p in paths_after},
            "paths.json ile paths_after.json farklı yollar içeriyor")
    yol_durum = Counter(p["status"] for p in paths_after)
    kesilen_yol = sum(1 for p in paths_after if any(n in engellendi for n in p["path"]))
    kontrol(yol_durum["kesildi"] == kesilen_yol,
            f"paths_after kesilen yol {yol_durum['kesildi']} != engellendi kayıt içeren yol {kesilen_yol}")
    notlar.append(f"Zafiyet: engellendi {len(engellendi)}, azaltildi {len(azaltildi)}; "
                  f"yol: kesildi {yol_durum['kesildi']}, zayifladi {yol_durum['zayifladi']}, acik {yol_durum['acik']}")
    once = sum(float(r["risk_before"]) for r in ba.values())
    sonra = sum(float(r["risk_after"]) for r in ba.values())
    notlar.append(f"Toplam artık risk: {once:.2f} -> {sonra:.2f} (%{(once - sonra) / once * 100:.2f})")


def onlem_kontrolleri():
    """Önlem motoru, uygulanmış kontrolleri sıfırdan ekleyince residual_risk.csv'yi üretmeli;
    onlem_secimi.json'daki taban mevcut sonuçlarla aynı olmalı."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("onlem_secimi", KOK / "ai" / "onlem_secimi.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    m = mod.Model()
    fark, _, sonra, _ = mod.dogrula(m)
    kontrol(not fark, f"onlem_secimi doğrulaması residual_risk.csv ile farklı: {sorted(fark)}")
    secim = json_oku("ai/onlem_secimi.json")
    kontrol(abs(secim["taban"]["yol_riski"] - sonra["yol_riski"]) < 1e-6,
            "onlem_secimi.json tabanı güncel değil: python ai/onlem_secimi.py")
    katalog = {r["onlem_id"] for r in csv_oku("inventory/onlem_katalogu.csv")}
    tekil = {r["onlem_id"] for r in csv_oku("ai/onlem_tekil.csv")}
    kontrol(katalog == tekil, "onlem_tekil.csv katalogla uyuşmuyor: python ai/onlem_secimi.py")
    en = secim["egri"]["tum"]["kesin"][-1]
    notlar.append(f"Önlem seçimi: {len(katalog)} aday, bütün önlemlerle ({en['efor_saat']:.0f} sa) yol riski "
                  f"{secim['taban']['yol_riski']:.2f} -> {en['yol_riski']:.2f}")


def kayit_sayisi(yol):
    p = KOK / yol
    if p.suffix == ".csv":
        return str(len(csv_oku(yol)))
    if p.suffix == ".json":
        return str(len(json_oku(yol)))
    return "-"


def belge_yaz():
    satirlar = [
        "# Sonuç dosyaları",
        "",
        "Rapordaki bütün sayılar bu dosyalardan gelir. `v-sonuclar` etiketinden sonra bu dosyalara "
        "dokunulmaz; hata bulunursa K1'e bildirilir ve düzeltme ayrı bir etiketle (`v-sonuclar-2`) yapılır.",
        "",
        "Bu belge `python tools/sonuc_kontrol.py` ile üretilir. SHA-256 özetleri, metin dosyalarında "
        "satır sonları LF'ye çevrilerek hesaplanır; Windows ve Linux klonları aynı özeti verir.",
        "",
        "## Dosyalar",
        "",
        "| Dosya | İçerik | Üreten | Komut | Kayıt | SHA-256 |",
        "|---|---|---|---|---|---|",
    ]
    for yol, ureten, komut, aciklama in DOSYALAR:
        p = KOK / yol
        ozet = f"`{sha256(p)[:16]}…`" if p.exists() else "**YOK**"
        satirlar.append(f"| `{yol}` | {aciklama} | {ureten} | `{komut}` | "
                        f"{kayit_sayisi(yol) if p.exists() else '-'} | {ozet} |")
    satirlar += [
        "",
        "Tam özetler (`sha256sum` çıktısıyla karşılaştırmak için; satır sonları LF):",
        "",
        "```",
        *[f"{sha256(KOK / y)}  {y}" for y, *_ in DOSYALAR if (KOK / y).exists()],
        "```",
        "",
        "## Yeniden üretim sırası",
        "",
        "Bir girdi değişirse sonraki adımların hepsi yeniden çalıştırılır:",
        "",
        "1. `python graph/generate_edges.py` → `python graph/find_paths.py`",
        "2. `python inventory/build_after_controls.py`",
        "3. `python ai/residual_risk.py`",
        "4. `python graph/cut_edges.py` → `python graph/paths_after.py`",
        "5. `python ai/before_after.py`",
        "6. `python graph/visualize_graph.py` ve `python graph/visualize_graph.py --after`; "
        "PNG'ler tarayıcıdan 1600×1000 pencerede alınır",
        "7. `python ai/onlem_secimi.py` (önlem kataloğu ya da residual_risk değişirse)",
        "8. `python tools/sonuc_kontrol.py`",
        "",
        "## Kontrol sonucu",
        "",
        *[f"- {n}" for n in notlar],
        *(["- Tutarsızlık yok."] if not hatalar else [f"- **HATA:** {h}" for h in hatalar]),
        "",
    ]
    BELGE.write_text("\n".join(satirlar), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sadece-kontrol", action="store_true")
    args = ap.parse_args()

    eksik = [y for y, *_ in DOSYALAR if not (KOK / y).exists()]
    kontrol(not eksik, f"eksik dosyalar: {eksik}")
    if not eksik:
        zafiyet_kontrolleri()
        tutarlilik_kontrolleri()
        onlem_kontrolleri()

    for n in notlar:
        print(n)
    if hatalar:
        print(f"\n{len(hatalar)} tutarsızlık:")
        for h in hatalar:
            print(f"  - {h}")
    else:
        print("Tutarsızlık yok.")
    if not args.sadece_kontrol:
        belge_yaz()
        print(f"Yazıldı: {BELGE.relative_to(KOK).as_posix()}")
    sys.exit(1 if hatalar else 0)


if __name__ == "__main__":
    main()
