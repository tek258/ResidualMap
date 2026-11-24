"""ResidualMap lab uygulaması.

Çalıştırma (repo kök dizininden):
    pip install -r requirements-app.txt
    streamlit run app/main.py
"""

import streamlit as st

from config import GRAFANA_PANO, GRAFANA_URL, TARGETS
from pipeline import runs
from steps import (ai_iz_panel, bulgular, grafik, hedef, isler, onlem, ortak, ortam_panel, ozet, rapor_panel,
                   savunma, tarama, tema)

st.set_page_config(page_title="ResidualMap", page_icon="🛡️", layout="wide")
tema.uygula()

ADIMLAR = ["Özet", "1. Hedef", "2. Tarama", "3. Bulgular", "4. Grafik", "5. Savunma testi", "6. Önlem seçimi"]

st.session_state.setdefault("run_id", None)
st.session_state.setdefault("target", None)
st.session_state.setdefault("adim", "Özet")

# Streamlit, o çalıştırmada ekranda olmayan seçim kutularının durumunu siler: başka adıma geçip
# dönünce bütçe, seçilen önlemler, tarama yöntemleri sıfırlanırdı. Değeri her çalıştırmada
# kendine yeniden atamak durumu korur. (Düğmeler ve tablolar bu listeye girmez.)
_KALICI = ("onlem_butce", "onlem_kesintisiz", "onlem_test", "onlem_secim", "onlem_grafik",
           "yontem_", "model_kayit_", "ozet_grafik", "savunma_grafik")
for _k in list(st.session_state):
    if isinstance(_k, str) and _k.startswith(_KALICI):
        st.session_state[_k] = st.session_state[_k]


with st.sidebar:
    tema.marka()
    meta = runs.load_meta(st.session_state["run_id"]).get("steps", {}) if st.session_state["run_id"] else {}
    bitti = {"1. Hedef": bool(st.session_state["run_id"]), "2. Tarama": "tarama" in meta,
             "3. Bulgular": "bulgular" in meta, "4. Grafik": "grafik" in meta,
             "5. Savunma testi": "saldiri_testi" in meta}
    adim = st.radio("Adım", ADIMLAR, key="adim", label_visibility="collapsed",
                    format_func=lambda a: ("✓  " if bitti.get(a) else "") + a)
    st.divider()
    if st.session_state["run_id"]:
        st.markdown(
            f"**Çalıştırma:** `{st.session_state['run_id']}`  \n"
            f"**Hedef:** {TARGETS[st.session_state['target']]['ad']}"
        )
        if runs.load_meta(st.session_state["run_id"]).get("ornek_veri"):
            st.caption("Örnek veri modu: canlı tarama yapılmadı.")
    else:
        st.markdown("Henüz çalıştırma yok.")

    ai_iz_panel.yan_menu()
    rapor_panel.yan_menu()
    isler.yan_menu()
    st.divider()
    ortam_panel.yan_menu()
    pano = ortak.grafana(GRAFANA_URL)
    st.link_button("Savunma panosu (Grafana) ↗", GRAFANA_PANO, disabled=not pano.ok,
                   use_container_width=True)
    st.caption(pano.mesaj if not pano.ok else
               "WAF engellemeleri, IDS alarmları ve IAM girişleri. Yeni sekmede açılır.")

if adim == "Özet":
    ozet.render()
elif adim == "1. Hedef":
    hedef.render()
elif adim == "6. Önlem seçimi":
    onlem.render()  # ekibin dondurulmuş sonuçlarıyla çalışır, çalıştırma gerektirmez
elif not st.session_state["run_id"]:
    st.header(adim)
    st.warning("Önce 1. adımda bir çalıştırma başlatın ya da önceki bir çalıştırmayı açın.")
elif adim == "2. Tarama":
    tarama.render()
elif adim == "3. Bulgular":
    bulgular.render()
elif adim == "4. Grafik":
    grafik.render()
else:
    savunma.render()
