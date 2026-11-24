"""0. adım: projenin sonucunu tek ekranda gösteren özet (ekibin dondurulmuş sonuçları)."""

import csv
import json

import streamlit as st

from config import AI_DIR, GRAPH_DIR
from steps import ortak, tema


def _oku():
    with open(AI_DIR / "residual_risk.csv", encoding="utf-8") as f:
        rr = list(csv.DictReader(f))
    yollar = json.loads((GRAPH_DIR / "paths_after.json").read_text(encoding="utf-8"))
    secim = json.loads((AI_DIR / "onlem_secimi.json").read_text(encoding="utf-8"))
    return rr, yollar, secim


def _ai_seridi():
    """Akış şeması: AI'nın girdiği adımlar vurgulu, altında bu çalıştırmadaki çağrı sayıları."""
    from collections import Counter

    from pipeline import ai_iz, runs
    from steps import ai_iz_panel
    rid = st.session_state.get("run_id")
    say = Counter(s["islem"] for s in ai_iz.oku(runs.run_dir(rid))) if rid else Counter()
    model = ai_iz_panel.hazir_sayisi()

    def n(*islemler):
        t = sum(say[i] for i in islemler)
        return f"Bu çalıştırmada {t} model çağrısı" if rid else ""

    adimlar = [
        ("1", "Hedef", "Yalnızca izin listesindeki yerel lab", None, ""),
        ("2", "Tarama", "ZAP, Trivy ve challenge verisi", None, ""),
        ("3", "Bulgular", "Envanter; yeni zafiyetler ekip kuralı ve MITRE CWE ile bağlanır",
         "Kuralın bağlayamadığı zafiyete hedef, giriş ve yetkinlik önerir", n(ai_iz.BAGLANTI)),
        ("4", "Grafik", "Saldırı yolları ve yol riski",
         f"Her zafiyete bağlamla risk skoru verir; gerekçesi görünür. Uzman uyumu 24/33 (CVSS 19/33)",
         n(ai_iz.SKOR, ai_iz.SKOR_TEK) or f"{model} kayıt modelle skorlandı"),
        ("5", "Savunma testi", "WAF, IDS, IAM lab'da sınanır", None, ""),
        ("6", "Önlem seçimi", "Bütçeye göre en iyi önlem bileşimi (kesin arama)",
         "Planı Türkçe açıklar; yazdığı her sayı denetlenir", n(ai_iz.PLAN)),
    ]
    html = ['<div class="rm-akis">']
    for no, ad, ne, ai, sayi in adimlar:
        html.append(
            f'<div class="adim{" ai" if ai else ""}"><div class="no">ADIM {no}</div>'
            f'<div class="ad">{ad}{"<span class=ai-rozet>AI</span>" if ai else ""}</div>'
            f'<div class="ne">{ne}</div>'
            + (f'<div class="ai-ne">{ai}</div>' if ai else "")
            + (f'<div class="sayi">{sayi}</div>' if ai and sayi else "") + "</div>")
    html.append("</div>")
    st.markdown("#### Yapay zekâ nerede?")
    st.caption("Yerel bir dil modeli (qwen2.5:7b, Ollama; bu makinede çalışır, veri dışarı çıkmaz) üç adımda "
               "karar verir. Hesapları model yapmaz; model yorumlar, önerir ve gerekçesini yazar. Her çağrı "
               "yan menüdeki \"AI izi\" penceresinde görünür.")
    st.markdown("".join(html), unsafe_allow_html=True)


def _git(ad):
    # Düğme geri çağırması: yan menüdeki adım seçimi bir sonraki çizimden önce değişir
    st.session_state["adim"] = ad


def render():
    rr, yollar, secim = _oku()
    once = sum(float(r["risk_before"]) for r in rr)
    sonra = sum(float(r["risk_after"]) for r in rr)
    test = [r for r in rr if r["dayanak"] == "test"]
    t_once = sum(float(r["risk_before"]) for r in test)
    t_sonra = sum(float(r["risk_after"]) for r in test)
    durum = {d: sum(p["status"] == d for p in yollar) for d in ("kesildi", "zayifladi", "acik")}
    b16 = next(x for x in secim["egri"]["tum"]["kesin"] if x["butce"] == 16)
    taban = secim["taban"]["yol_riski"]

    st.markdown(
        '<div class="rm-hero"><div class="ust">ResidualMap · OWASP Juice Shop lab</div><h1>Kritik varlıklara hangi yollarla ulaşılır, '
        'sınırlı kaynakla risk en çok nasıl azalır?</h1>'
        '<p>OWASP Juice Shop üzerinde izole bir lab: tarama → envanter → AI risk skoru → saldırı grafiği → '
        'savunma kontrolleri ve testleri → önlem seçimi.</p></div>', unsafe_allow_html=True)

    tema.kartlar([
        ("Zafiyet", f"{len(rr)}", "3 kaynak: ZAP, Trivy, challenge"),
        ("Saldırı yolu", f"{len(yollar)}", "5 kritik varlığa"),
        ("Artık risk düşüşü", f"%{(1 - sonra / once) * 100:.0f}",
         f"{once:.0f} → {sonra:.0f}; test kanıtlı %{(1 - t_sonra / t_once) * 100:.0f}", "savunma"),
        ("Kesilen yol", f"{durum['kesildi']} / {len(yollar)}",
         f"{durum['zayifladi']} zayıfladı · {durum['acik']} açık", "savunma"),
        ("16 saatlik önlem planı", f"−%{(1 - b16['yol_riski'] / taban) * 100:.0f}",
         f"yol riski {taban:.0f} → {b16['yol_riski']:.0f}", "vurgu"),
    ])
    st.caption("Kartlar ve aşağıdaki grafik ekibin dondurulmuş 36 kayıtlık sonuçlarıdır. Kendi seçiminizle "
               "yapılan bir çalıştırmanın sonuçları 4-6. adımlarda ve çalıştırma raporunda görünür.")
    st.write("")
    _ai_seridi()
    st.write("")
    st.markdown("#### Saldırı grafiği: kontroller öncesi ve sonrası")
    st.caption("Kesilen kenarlar gri ve kesikli, zayıflayanlar turuncu. Düğümlerin üstüne gelince ayrıntı görünür.")
    dosyalar = {"Kontroller sonrası": "attack_graph_after.html", "Kontroller öncesi": "attack_graph_v2.html"}
    secili = ortak.grafik_secici(list(dosyalar), "ozet_grafik")
    ortak.grafik_goster(GRAPH_DIR / dosyalar[secili], yukseklik=700, tuval=620)
    st.write("")
    a, b, _ = st.columns([1, 1, 3])
    a.button("Demoyu başlat →", type="primary", width="stretch", on_click=_git, args=("1. Hedef",))
    b.button("Önlem planına git", width="stretch", on_click=_git, args=("6. Önlem seçimi",))
