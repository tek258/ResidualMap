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
    st.write("")
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
