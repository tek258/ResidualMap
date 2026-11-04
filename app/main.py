"""ResidualMap lab uygulaması.

Çalıştırma (repo kök dizininden):
    pip install -r requirements-app.txt
    streamlit run app/main.py
"""

import streamlit as st

from config import TARGETS
from steps import bulgular, hedef, tarama

st.set_page_config(page_title="ResidualMap", page_icon="🛡️", layout="wide")

ADIMLAR = ["1. Hedef", "2. Tarama", "3. Bulgular", "4. Grafik"]
YAKINDA = {  # henüz yazılmamış adımlar ve hangi issue'da geleceği
    "4. Grafik": "U4",
}

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
    else:
        st.markdown("Henüz çalıştırma yok.")

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
    st.header(adim)
    st.info(f"Bu adım {YAKINDA[adim]} ile eklenecek.")
