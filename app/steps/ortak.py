"""Adımların ortak kullandığı yardımcılar."""

import streamlit as st

from pipeline import docker_check


@st.cache_data(ttl=10, show_spinner=False)
def durumlar(konteyner):
    """Docker ve hedef konteyner durumu (her etkileşimde sorgulamamak için 10 sn önbellek)."""
    return docker_check.docker_durumu(), docker_check.konteyner_durumu(konteyner)
