"""Adımların ortak kullandığı yardımcılar."""

import streamlit as st

from pipeline import docker_check


@st.cache_data(ttl=10, show_spinner=False)
def durumlar(konteyner):
    """Docker ve hedef konteyner durumu (her etkileşimde sorgulamamak için 10 sn önbellek)."""
    return docker_check.docker_durumu(), docker_check.konteyner_durumu(konteyner)


@st.cache_data(ttl=10, show_spinner=False)
def grafana(url):
    return docker_check.grafana_durumu(url)


@st.cache_data(ttl=10, show_spinner=False)
def ollama():
    from pipeline import ai_skor
    return ai_skor.ollama_durumu()
