"""ResidualMap lab uygulaması.

Çalıştırma (repo kök dizininden):
    pip install -r requirements-app.txt
    streamlit run app/main.py
"""

import streamlit as st

from config import GRAFANA_PANO, GRAFANA_URL, TARGETS
from pipeline import runs
from steps import bulgular, grafik, hedef, ortak, tarama

st.set_page_config(page_title="ResidualMap", page_icon="🛡️", layout="wide")

ADIMLAR = ["1. Hedef", "2. Tarama", "3. Bulgular", "4. Grafik"]

st.session_state.setdefault("run_id", None)
st.session_state.setdefault("target", None)

with st.sidebar:
    st.title("ResidualMap")
    st.caption("Saldırı grafiği tabanlı zafiyet değerlendirme")
    adim = st.radio("Adım", ADIMLAR, label_visibility="collapsed")
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

    st.divider()
    pano = ortak.grafana(GRAFANA_URL)
    st.link_button("Savunma panosu (Grafana) ↗", GRAFANA_PANO, disabled=not pano.ok,
                   use_container_width=True)
    st.caption(pano.mesaj if not pano.ok else
               "WAF engellemeleri, IDS alarmları ve IAM girişleri. Yeni sekmede açılır.")

if adim == "1. Hedef":
    hedef.render()
elif not st.session_state["run_id"]:
    st.header(adim)
    st.warning("Önce 1. adımda bir çalıştırma başlatın ya da önceki bir çalıştırmayı açın.")
elif adim == "2. Tarama":
    tarama.render()
elif adim == "3. Bulgular":
    bulgular.render()
else:
    grafik.render()
