"""1. adım: lab hedefinin seçilmesi ve çalıştırmanın başlatılması."""

import streamlit as st

from config import TARGETS
from pipeline import runs
from steps.ortak import durumlar as _durumlar


def render():
    st.header("1. Hedef")
    st.caption(
        "Tarama yalnızca kendi lab ortamınızda çalışan, kasıtlı olarak açıklı "
        "uygulamalara yapılabilir. Liste dışında bir adres taranamaz."
    )

    keys = list(TARGETS)
    secili = st.session_state.get("target") or keys[0]
    target_key = st.selectbox(
        "Lab hedefi",
        keys,
        index=keys.index(secili),
        format_func=lambda k: TARGETS[k]["ad"],
    )
    t = TARGETS[target_key]

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**{t['ad']}**  \n{t['aciklama']}")
        st.markdown(
            f"- Konteyner: `{t['konteyner']}`\n"
            f"- İmaj (Trivy): `{t['imaj']}`\n"
            f"- Web adresi (ZAP): `{t['zap_url']}`"
        )
    with col2:
        docker, konteyner = _durumlar(t["konteyner"])
        (st.success if docker.ok else st.error)(docker.mesaj)
        if docker.ok:
            (st.success if konteyner.ok else st.warning)(konteyner.mesaj)
        if st.button("Durumu yenile"):
            _durumlar.clear()
            st.rerun()
        if not (docker.ok and konteyner.ok):
            st.info("Canlı tarama için lab ortamı çalışmalı. Ortam kapalıyken de "
                    "çalıştırma başlatıp 2. adımda mevcut ham dosyaları yükleyebilirsiniz.")

    st.divider()
    st.subheader("Çalıştırma")

    if st.button("Yeni çalıştırma başlat", type="primary"):
        run_id = runs.new_run(target_key)
        st.session_state["run_id"] = run_id
        st.session_state["target"] = target_key
        st.success(f"Çalıştırma oluşturuldu: `{run_id}`. Sol menüden 2. adıma geçin.")

    onceki = runs.list_runs(target_key)
    if onceki:
        with st.expander(f"Önceki çalıştırmayı aç ({len(onceki)})"):
            ids = [m["run_id"] for m in onceki]
            secim = st.selectbox(
                "Çalıştırma",
                ids,
                format_func=lambda i: f"{i}  ·  tamamlanan adımlar: "
                                      f"{', '.join(next(m for m in onceki if m['run_id'] == i)['steps']) or 'yok'}",
            )
            if st.button("Aç"):
                st.session_state["run_id"] = secim
                st.session_state["target"] = target_key
                st.success(f"`{secim}` açıldı.")
