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


_SIGDIR = """
<script>
// Uygulama ekliyor: sekmedeki grafik gizliyken sıfır genişlikle çiziliyor; görünür olunca
// (iframe boyutu değişince) ve fizik yerleşimi bitince yeniden sığdırılır.
(function () {
  if (typeof network === "undefined") return;
  var w = window.innerWidth;
  function sigdir() { if (window.innerWidth > 0) network.fit({animation: false}); }
  network.once("stabilizationIterationsDone", sigdir);
  window.addEventListener("resize", function () {
    if (window.innerWidth !== w) { w = window.innerWidth; sigdir(); }
  });
})();
</script>
"""


def grafik_html(metin):
    """pyvis HTML'ine sekme içinde doğru sığdırma betiğini ekler (dosyaya yazılmaz)."""
    return metin.replace("</body>", _SIGDIR + "</body>") if "</body>" in metin else metin + _SIGDIR
