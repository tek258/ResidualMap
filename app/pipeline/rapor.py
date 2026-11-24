"""Çalıştırma raporu: bir çalıştırmanın bütün sonuçları tek bir HTML dosyasında.

Rapor uygulamanın ürettiği dosyalardan derlenir (meta.json, inventory.csv, ai_skorlari.csv,
graph/paths.json, ai_iz.jsonl); hiçbir sayı yeniden hesaplanmaz. Önlem planı 6. adımdaki
seçimden gelir (çağıran hazırlar). Tarayıcıda açılır, "Yazdır > PDF olarak kaydet" ile PDF olur.
"""

import csv
import datetime
import html
import json
from collections import Counter

from config import TARGETS
from pipeline import ai_iz, ai_skor, runs

HEDEF_ADI = {"node_target_admin": "Yönetici erişimi", "node_target_rce": "Kod çalıştırma",
             "node_target_account_takeover": "Hesap ele geçirme", "node_target_leak": "Veri sızıntısı",
             "node_target_dos": "Hizmet kesintisi"}

CSS = """
:root { --ink:#141a2a; --ink2:#5b6377; --ink3:#8a92a6; --line:#eceef4; --bg:#f6f7fb; --vurgu:#4f5bd5;
  --ai:#6d5ce8; --iyi:#1f9d8f; --kotu:#e5484d; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 'Plus Jakarta Sans', system-ui, -apple-system,
  'Segoe UI', sans-serif; }
main { max-width:1080px; margin:0 auto; padding:40px 24px 64px; }
h1 { font-size:30px; margin:4px 0 6px; letter-spacing:-.01em; }
h2 { font-size:20px; margin:40px 0 4px; letter-spacing:-.01em; }
h3 { font-size:16px; margin:20px 0 6px; }
.ust { color:var(--vurgu); font-weight:600; font-size:13px; }
.alt { color:var(--ink2); margin:0 0 4px; }
.not { color:var(--ink3); font-size:13px; margin:4px 0 12px; }
.kartlar { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin:20px 0 4px; }
.kart { background:#fff; border:1px solid var(--line); border-radius:16px; padding:16px 18px; }
.kart .e { color:var(--ink3); font-size:12px; font-weight:600; }
.kart .d { font-size:26px; font-weight:700; margin-top:4px; }
.kart .a { color:var(--ink2); font-size:12.5px; margin-top:2px; }
.kart.ai { background:linear-gradient(160deg,#f1efff,#fff 85%); border-color:#d9d6fb; }
.kart.ai .d { color:var(--ai); }
.kart.iyi .d { color:var(--iyi); }
table { width:100%; border-collapse:collapse; background:#fff; border:1px solid var(--line); border-radius:12px;
  overflow:hidden; font-size:13.5px; margin:8px 0; }
th { text-align:left; background:#fafbfd; color:var(--ink2); font-weight:600; font-size:12.5px; }
th, td { padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
tr:last-child td { border-bottom:none; }
td.sayi, th.sayi { text-align:right; white-space:nowrap; font-variant-numeric:tabular-nums; }
code { font-family:'JetBrains Mono', ui-monospace, Consolas, monospace; font-size:12.5px; }
.rozet { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11.5px; font-weight:700; }
.rozet.ai { background:var(--ai); color:#fff; }
.kutu { background:#fff; border:1px solid var(--line); border-radius:16px; padding:16px 20px; margin:10px 0; }
.kutu.ai { border-color:#d9d6fb; background:linear-gradient(160deg,#f6f4ff,#fff 70%); }
.uyari { color:#b26a00; }
iframe { width:100%; height:760px; border:1px solid var(--line); border-radius:16px; background:#fff; }
footer { color:var(--ink3); font-size:12.5px; margin-top:48px; border-top:1px solid var(--line); padding-top:14px; }
@media print { body { background:#fff; } main { padding:0; } .kart, .kutu, table { break-inside:avoid; }
  iframe { display:none; } .yalniz-ekran { display:none; } h2 { break-after:avoid; } }
"""


def _e(x):
    return html.escape("" if x is None else str(x))


def _tablo(basliklar, satirlar, sayisal=()):
    bas = "".join(f'<th class="{"sayi" if b in sayisal else ""}">{_e(b)}</th>' for b in basliklar)
    govde = "".join("<tr>" + "".join(
        f'<td class="{"sayi" if b in sayisal else ""}">{h if isinstance(h, _Ham) else _e(h)}</td>'
        for b, h in zip(basliklar, s)) + "</tr>" for s in satirlar)
    return f"<table><thead><tr>{bas}</tr></thead><tbody>{govde}</tbody></table>"


class _Ham(str):
    """Kaçırılmadan yazılacak (zaten güvenli) HTML parçası."""


def _kart(etiket, deger, alt="", tur=""):
    return (f'<div class="kart {tur}"><div class="e">{_e(etiket)}</div><div class="d">{_e(deger)}</div>'
            f'<div class="a">{_e(alt)}</div></div>')


def _oku_csv(yol):
    if not yol.exists():
        return []
    with open(yol, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _yol_adi(p):
    return " → ".join(n.replace("node_entry_", "giriş: ").replace("node_target_", "hedef: ") for n in p)


def olustur(run_id, onlem=None, grafik_ekle=True):
    """HTML metni. onlem: 6. adımdaki plan (steps/rapor_panel.py hazırlar) ya da None."""
    rdir = runs.run_dir(run_id)
    meta = runs.load_meta(run_id)
    adimlar = meta.get("steps", {})
    hedef = TARGETS.get(meta.get("target"), {}).get("ad", meta.get("target", ""))
    inv = _oku_csv(rdir / "inventory.csv")
    paths = json.loads((rdir / "graph" / "paths.json").read_text(encoding="utf-8")) \
        if (rdir / "graph" / "paths.json").exists() else []
    skorlar = ai_skor.tablo(rdir) if inv else []
    iz = ai_iz.oku(rdir)
    test = adimlar.get("saldiri_testi") or {}
    simdi = datetime.datetime.now().strftime("%d.%m.%Y %H:%M")

    b = []
    b.append(f'<div class="ust">ResidualMap · çalıştırma raporu</div><h1>{_e(hedef)} · <code>{_e(run_id)}</code></h1>'
             f'<p class="alt">Rapor tarihi {simdi}.'
             + (" Örnek veri modu: canlı tarama yapılmadı, ekibin ham dosyaları kullanıldı." if meta.get("ornek_veri") else "")
             + "</p><p class=\"not\">Bütün testler yalnızca izole yerel Docker lab'ında, izin listesindeki hedefe karşı yapıldı.</p>")

    # --- özet kartları ---
    ai_skorlu = sum(1 for s in skorlar if s["AI skoru"] is not None)
    en_riskli = max((p.get("path_risk") or 0 for p in paths), default=0)
    test_ok = sum(1 for s in test.get("satirlar", []) if s.get("Durum") == "✅")
    kartlar = [
        _kart("Zafiyet", len(inv), "envanterdeki kayıt"),
        _kart("Saldırı yolu", len(paths), f"en yüksek yol riski {en_riskli:.2f}" if paths else "grafik üretilmedi"),
        _kart("AI risk skoru", f"{ai_skorlu}/{len(inv)}", "kayıt yerel modelle skorlandı", "ai"),
        _kart("Model çağrısı", len(iz), "bu çalıştırmada (AI izi)", "ai"),
    ]
    if test.get("satirlar"):
        kartlar.append(_kart("Savunma testi", f"{test_ok}/{len(test['satirlar'])}", "beklenen sonuç", "iyi"))
    if onlem:
        kartlar.append(_kart("Önlem planı", f"−%{onlem['dusus_yuzde']:.0f}",
                             f"yol riski {onlem['once']['yol']:.0f} → {onlem['sonra']['yol']:.0f}", "iyi"))
    b.append('<div class="kartlar">' + "".join(kartlar) + "</div>")

    # --- 1. tarama ---
    b.append("<h2>1. Tarama</h2><p class=\"not\">Ham verinin kaynağı ve özeti.</p>")
    tarama = adimlar.get("tarama", {})
    if tarama:
        b.append(_tablo(["Kaynak", "Yöntem", "Durum", "Özet", "Süre (sn)"], [
            [k, v.get("yontem"), "✅" if v.get("ok") else "❌",
             ", ".join(f"{a}: {c}" for a, c in (v.get("ozet") or {}).items()) or v.get("mesaj"), v.get("sure_sn")]
            for k, v in tarama.items()], sayisal=("Süre (sn)",)))
    else:
        b.append('<p class="alt">Bu çalıştırmada tarama adımı kaydı yok (dondurulmuş envanter kullanıldı).</p>')

    # --- 2. bulgular ve bağlantı ---
    bul = adimlar.get("bulgular", {})
    b.append("<h2>2. Bulgular ve grafiğe bağlantı</h2>")
    if "kayit" in bul:
        b.append(f'<p class="alt">{bul["kayit"]} kayıt: {bul.get("envanterden", 0)} ekibin envanterinden, '
                 f'{bul.get("yeni", 0)} yeni.</p>')
    elif bul.get("kaynak"):
        b.append(f'<p class="alt">Kaynak: {_e(bul["kaynak"])}.</p>')
    yeni_idler = set(bul.get("varsayilanlar", {}))
    yeniler = [r for r in inv if r["vuln_id"] in yeni_idler]
    if yeniler:
        say = Counter(r.get("hedef_kaynagi") or "belirsiz" for r in yeniler)
        belirsiz = [r["vuln_id"] for r in yeniler if not r.get("hedef")]
        b.append('<p class="alt">Yeni kayıtların saldırı grafiğine bağlantısının kaynağı: '
                 + ", ".join(f"<b>{_e(k)}</b> {v}" for k, v in say.most_common()) + "."
                 + (f' <span class="uyari">Hedefi belirsiz: {_e(", ".join(belirsiz))}.</span>' if belirsiz else "")
                 + "</p>")
        # Kuraldan gelenler yalnızca sayılır; tabloda AI'nın, kullanıcının karar verdiği ve belirsiz kalanlar
        yeniler = [r for r in yeniler if r.get("hedef_kaynagi") in ("AI önerisi", "elle", "", None)]
        if yeniler:
            b.append('<p class="alt">AI önerisiyle, elle bağlanan ya da belirsiz kalan kayıtlar:</p>')
        b.append(_tablo(["Kayıt", "Ad", "CWE", "Hedef", "Giriş", "Kaynak", "Gerekçe"], [
            [r["vuln_id"], r.get("name", "")[:70], r.get("cwe_id", ""), HEDEF_ADI.get(r.get("hedef"), "belirsiz"),
             r.get("entry_point", ""),
             _Ham('AI önerisi <span class="rozet ai">AI</span>') if r.get("hedef_kaynagi") == "AI önerisi"
             else r.get("hedef_kaynagi") or "belirsiz",
             r.get("hedef_gerekcesi", "")] for r in sorted(yeniler, key=lambda r: r["vuln_id"])[:40]]))
        if len(yeniler) > 40:
            b.append(f'<p class="not">İlk 40 kayıt gösterildi ({len(yeniler)} kayıttan).</p>')

    # --- 3. AI risk skoru ---
    b.append('<h2>3. AI risk skoru <span class="rozet ai">AI</span></h2>'
             '<p class="not">Yerel dil modeli (model v2, qwen2.5:7b, temperature 0, sabit seed) her zafiyete '
             'bağlamla 0-10 arası risk skoru verir ve gerekçesini yazar. Uzman etiketleriyle sınıf uyumu 24/33, '
             'yalnızca CVSS 19/33 (docs/model-v2-degerlendirme.md). En yüksek 15 kayıt:</p>')
    if skorlar:
        b.append(_tablo(["AI sırası", "Kayıt", "Ad", "AI skoru", "Sınıf", "CVSS", "CVSS sırası", "Gerekçe"], [
            [s["AI sırası"], s["Kayıt"], s["Ad"][:60], f'{s["AI skoru"]:.1f}' if s["AI skoru"] is not None else "-",
             s["AI sınıfı"], f'{s["CVSS"]:.1f}' if s["CVSS"] is not None else "-", s["CVSS sırası"] or "-",
             s["AI gerekçesi"]] for s in skorlar[:15]], sayisal=("AI sırası", "AI skoru", "CVSS", "CVSS sırası")))
        farkli = sorted((s for s in skorlar if s["AI skoru"] is not None and s["CVSS"] is not None),
                        key=lambda s: -abs(s["AI skoru"] - s["CVSS"]))[:3]
        if farkli:
            b.append('<p class="alt">Modelin CVSS\'ten en çok ayrıldığı kayıtlar: ' + "; ".join(
                f'{_e(s["Kayıt"])} (AI {s["AI skoru"]:.1f}, CVSS {s["CVSS"]:.1f})' for s in farkli) + ".</p>")

    # --- 4. saldırı grafiği ---
    b.append("<h2>4. Saldırı grafiği</h2>")
    if paths:
        hedef_say = Counter(HEDEF_ADI.get(p["target"], p["target"]) for p in paths)
        b.append(f'<p class="alt">{len(paths)} yol; hedeflere göre: '
                 + ", ".join(f"{_e(k)} {v}" for k, v in hedef_say.most_common()) + ". En riskli 10 yol:</p>")
        b.append(_tablo(["#", "Yol", "Hedef", "Yol riski"], [
            [i, _yol_adi(p["path"]), HEDEF_ADI.get(p["target"], p["target"]),
             f'{p["path_risk"]:.2f}' if p.get("path_risk") is not None else "-"]
            for i, p in enumerate(sorted(paths, key=lambda p: -(p.get("path_risk") or 0))[:10], start=1)],
            sayisal=("#", "Yol riski")))
        grafik = rdir / "graph" / "attack_graph.html"
        if grafik_ekle and grafik.exists():
            b.append('<p class="not yalniz-ekran">Etkileşimli grafik (sürükleyip yakınlaştırabilirsiniz; '
                     'internet bağlantısı gerektirir, yazdırmada gösterilmez):</p>'
                     f'<iframe srcdoc="{html.escape(grafik.read_text(encoding="utf-8"), quote=True)}"></iframe>')
    else:
        b.append('<p class="alt">Grafik bu çalıştırmada üretilmedi.</p>')

    # --- 5. savunma testi ---
    b.append("<h2>5. Savunma testi</h2>")
    if test.get("satirlar"):
        b.append(f'<p class="alt">{_e(test.get("mesaj"))} ({_e(test.get("zaman", "").replace("T", " "))}, '
                 f'{test.get("sure_sn")} sn). Her saldırı isteğinin yanında aynı uç noktaya zararsız bir kontrol isteği var.</p>')
        b.append(_tablo(["Bölüm", "İstek", "Zafiyet", "HTTP", "Sonuç", "Durum"], [
            [s.get("Bölüm"), s.get("İstek"), s.get("Zafiyet"), s.get("HTTP") or "", s.get("Sonuç"), s.get("Durum")]
            for s in test["satirlar"]], sayisal=("HTTP",)))
    else:
        b.append('<p class="alt">Savunma testi bu çalıştırmada çalıştırılmadı.</p>')

    # --- 6. önlem planı ---
    b.append("<h2>6. Önlem planı</h2>")
    if onlem:
        b.append(f'<p class="alt">Bütçe {onlem["butce"]} saat, {_e(onlem["dayanak"])}. Yol riski '
                 f'{onlem["once"]["yol"]:.2f} → {onlem["sonra"]["yol"]:.2f} (−%{onlem["dusus_yuzde"]:.1f}), '
                 f'kesilen yol {onlem["once"]["kesik"]} → {onlem["sonra"]["kesik"]} / {onlem["toplam_yol"]}, '
                 f'harcanan efor {onlem["efor"]:.0f} saat. Önlemler önerilir, lab\'a uygulanmaz.</p>')
        b.append(_tablo(["Önlem", "Tür", "Zafiyetler", "Efor (sa)", "Kesinti", "Tek başına yol riski düşüşü"],
                        [[o["ad"], o["tur"], o["zafiyetler"], o["efor"], o["kesinti"], o["dusus"]] for o in onlem["onlemler"]],
                        sayisal=("Efor (sa)", "Tek başına yol riski düşüşü")))
        if onlem.get("aciklama"):
            metin, uyari = onlem["aciklama"]
            b.append('<div class="kutu ai"><b>AI açıklaması</b> <span class="rozet ai">AI</span>'
                     + "".join(f"<p>{_e(p)}</p>" for p in metin.split("\n") if p.strip())
                     + (f'<p class="uyari">Sayı denetimi: metinde hesaplanan verilerde olmayan sayılar var: '
                        f'{_e(", ".join(f"{x:g}" for x in uyari))}.</p>' if uyari else
                        '<p class="not">Sayı denetimi: metindeki bütün sayılar hesaplanan değerlerde var.</p>')
                     + "</div>")
    else:
        b.append('<p class="alt">6. adımda henüz bir plan seçilmedi.</p>')

    # --- 7. AI izi ---
    b.append('<h2>7. AI izi <span class="rozet ai">AI</span></h2>')
    if iz:
        dagilim = Counter(s["islem"] for s in iz)
        b.append(f'<p class="alt">Bu çalıştırmada yerel modele {len(iz)} çağrı yapıldı; '
                 f'{sum(1 for s in iz if s.get("ok"))} geçerli yanıt, ortalama {sum(s["sure_sn"] for s in iz) / len(iz):.1f} sn. '
                 "Model bu makinede çalıştı, veri dışarı gönderilmedi. Tam kayıt (prompt ve yanıtlar): "
                 f'<code>runs/{_e(run_id)}/{ai_iz.DOSYA}</code>.</p>')
        b.append(_tablo(["İşlem", "Adım", "Çağrı"], [[k, ai_iz.ADIM.get(k, ""), v] for k, v in dagilim.most_common()],
                        sayisal=("Çağrı",)))
    else:
        b.append('<p class="alt">Bu çalıştırmada uygulama modeli çağırmadı; AI skorları ekibin aynı modelle '
                 'ürettiği hazır sonuçtan geldi (ai/results_v2_llm.csv).</p>')

    b.append("<footer>ResidualMap · Saldırı grafiği tabanlı zafiyet değerlendirme. Rapor uygulamanın ürettiği "
             "dosyalardan derlendi; sayılar yeniden hesaplanmadı. Sınırlılıklar: yeni kayıtların bazı alanları "
             "varsayılan değerlerdedir; AI skoru bant içinde ayırt edicilikte zayıftır (docs/model-v2-degerlendirme.md).</footer>")

    return ("<!doctype html><html lang=\"tr\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>ResidualMap raporu {_e(run_id)}</title>"
            "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">"
            "<link href=\"https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700&family=JetBrains+Mono&display=swap\" rel=\"stylesheet\">"
            f"<style>{CSS}</style></head><body><main>{''.join(b)}</main></body></html>")
