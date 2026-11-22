"""Ortak görünüm: yazı tipi, kartlar, rozetler, yan menüdeki adım çubuğu."""

import streamlit as st

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
html, body, .stApp, .stMarkdown p, .stMarkdown li, h1, h2, h3, label, button p, [data-testid="stMetricValue"],
[data-testid="stMetricLabel"] { font-family: 'Plus Jakarta Sans', system-ui, sans-serif; }
[data-testid="stIconMaterial"] { font-family: 'Material Symbols Rounded' !important; }
code, .stCode, pre { font-family: 'JetBrains Mono', ui-monospace, monospace !important; }
.stApp { background: #f6f7fb; }
[data-testid="stHeader"] { background: transparent; }
footer, #MainMenu, [data-testid="stToolbar"] { visibility: hidden; }
.block-container { padding-top: 2.6rem; padding-left: 3.2rem; padding-right: 3.2rem; max-width: 1360px; }
h1, h2, h3 { letter-spacing: -0.015em; color:#141a2a; }
h2, h3 { margin-top: 1.4rem; }
.stCaption, [data-testid="stCaptionContainer"] { color:#6b7387 !important; }

/* Yan menü: beyaz, ince çizgi */
[data-testid="stSidebar"] { background: #ffffff; border-right: 1px solid #eceef4; }
[data-testid="stSidebar"] .block-container, [data-testid="stSidebarContent"] { padding-top: 1.2rem; }
.rm-marka { display:flex; align-items:center; gap:.65rem; margin:.3rem 0 .15rem; }
.rm-marka .logo { width:36px; height:36px; border-radius:11px; display:grid; place-items:center;
  background: linear-gradient(135deg,#6d7cff,#38c2b3); color:#fff; font-weight:700; font-size:.9rem; }
.rm-marka .ad { font-size:1.2rem; font-weight:700; color:#141a2a; }
.rm-alt { color:#8a92a6; font-size:.8rem; margin:0 0 1.3rem; }

[data-testid="stSidebar"] [role="radiogroup"] { gap: 4px; width:100%; }
[data-testid="stSidebar"] [data-testid="stRadioOption"] { width:100%; padding: .6rem .8rem; border-radius: 12px; margin:0;
  transition: background .15s; box-sizing:border-box; }
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child:not([data-testid]) { display:none !important; }
[data-testid="stSidebar"] [data-testid="stRadioOption"]:hover { background:#f3f4fa; }
[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"] { background:#eef0ff; }
[data-testid="stSidebar"] [data-testid="stRadioOption"][data-selected="true"] p { color:#3f4bc4; font-weight:600; }
[data-testid="stSidebar"] [role="radiogroup"] p { font-size:.95rem; color:#3a4256; }
[data-testid="stSidebar"] hr { border-color:#eef0f5; }

/* Kart: beyaz, yumuşak gölge, bol iç boşluk */
.rm-kart { background:#ffffff; border:1px solid #eceef4; border-radius:18px; padding:1.25rem 1.35rem; height:100%;
  box-shadow: 0 1px 2px rgba(20,26,42,.04), 0 8px 24px rgba(20,26,42,.05); }
.rm-kart .etiket { color:#8a92a6; font-size:.8rem; font-weight:600; }
.rm-kart .deger { font-size:2.1rem; font-weight:700; color:#141a2a; line-height:1.15; margin-top:.35rem; }
.rm-kart .alt { color:#7a8296; font-size:.85rem; margin-top:.3rem; }
.rm-kart.savunma .deger { color:#1f9d8f; }
.rm-kart.vurgu { background:#fff7f6; border-color:#fde3df; }
.rm-kart.vurgu .deger { color:#e5484d; }

/* Adım başlığı */
.rm-baslik .no { color:#4f5bd5; font-weight:600; font-size:.85rem; }
.rm-baslik h1 { margin:.15rem 0 .25rem; font-size:2.1rem; }
.rm-baslik .soru { color:#5b6377; font-size:1.08rem; margin-bottom:1.4rem; }

/* Rozet */
.rm-rozet { display:inline-block; padding:.15rem .6rem; border-radius:999px; font-size:.78rem; font-weight:600; }
.rm-rozet.kesildi { background:#eef0f4; color:#5b6377; }
.rm-rozet.zayif { background:#fff3df; color:#b26a00; }
.rm-rozet.acik { background:#eef0ff; color:#3f4bc4; }

/* Özet kahraman alanı */
.rm-hero { background: linear-gradient(120deg,#eef0ff 0%,#f2fbf9 60%,#ffffff 100%);
  border:1px solid #e7e9f6; border-radius:24px; padding:2.2rem 2.4rem; margin-bottom:1.6rem; }
.rm-hero .ust { color:#4f5bd5; font-weight:600; font-size:.88rem; margin-bottom:.5rem; }
.rm-hero h1 { font-size:2.15rem; margin:0 0 .6rem; line-height:1.2; }
.rm-hero p { color:#5b6377; font-size:1.05rem; margin:0; max-width: 860px; line-height:1.6; }

/* Tablolar, kutular, girdiler: yuvarlak ve yumuşak */
[data-testid="stDataFrame"], [data-testid="stExpander"], [data-testid="stVerticalBlockBorderWrapper"] {
  border-radius:16px !important; }
[data-testid="stMetric"] { background:#fff; border:1px solid #eceef4; border-radius:16px; padding:1rem 1.1rem;
  box-shadow: 0 8px 24px rgba(20,26,42,.04); }
.stButton > button { border-radius:12px; padding:.55rem 1.1rem; }
iframe { border-radius:16px; }
.rm-gorsel img { border-radius:16px; box-shadow: 0 8px 24px rgba(20,26,42,.08); }
</style>
"""


def uygula():
    st.markdown(CSS, unsafe_allow_html=True)


def marka():
    st.markdown('<div class="rm-marka"><div class="logo">RM</div><div class="ad">ResidualMap</div></div>'
                '<div class="rm-alt">Saldırı grafiği tabanlı zafiyet değerlendirme</div>', unsafe_allow_html=True)


def baslik(no, ad, soru):
    st.markdown(f'<div class="rm-baslik"><div class="no">{no}</div><h1>{ad}</h1>'
                f'<div class="soru">{soru}</div></div>', unsafe_allow_html=True)


def kart(etiket, deger, alt="", tur=""):
    return (f'<div class="rm-kart {tur}"><div class="etiket">{etiket}</div>'
            f'<div class="deger">{deger}</div><div class="alt">{alt}</div></div>')


def kartlar(liste):
    for kol, k in zip(st.columns(len(liste)), liste):
        kol.markdown(kart(*k), unsafe_allow_html=True)
