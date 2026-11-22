"""Adımların ortak kullandığı yardımcılar."""

import streamlit as st

from pipeline import docker_check


@st.cache_data(ttl=60, show_spinner=False)
def durumlar(konteyner):
    """Docker ve hedef konteyner durumu. Windows'ta `docker` komutu 1-3 sn sürdüğü için 60 sn önbellek;
    1. adımdaki "Durumu yenile" önbelleği temizler."""
    return docker_check.docker_durumu(), docker_check.konteyner_durumu(konteyner)


@st.cache_data(ttl=60, show_spinner=False)
def grafana(url):
    return docker_check.grafana_durumu(url)


@st.cache_data(ttl=60, show_spinner=False)
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


# Uygulamanın açık temasına uyum: graph/visualize_graph.py'nin koyu renkleri yalnızca ekranda
# değiştirilir; repodaki HTML dosyaları ve K3'ün kodu aynı kalır.
_ACIK_RENKLER = [
    ("#141820", "#ffffff"),                               # tuval zemini
    ("#f5f7fa", "#1d2433"),                               # düğüm etiketleri, başlık, panel yazısı
    ("rgba(20, 24, 32, 0.92)", "rgba(255, 255, 255, 0.96)"),   # lejant ve en riskli yollar paneli
    ("border: 1px solid #4a5568", "border: 1px solid #e3e6ef"),
    ("rgba(255,255,255,0.14)", "rgba(20,26,42,0.10)"),
    ("color: #90caf9", "color: #4f5bd5"),                  # lejant başlığı
    ("box-shadow: 0 4px 16px rgba(0,0,0,0.45)", "box-shadow: 0 8px 24px rgba(20,26,42,0.10)"),
    ("#f9e79f", "#f4d03f"),                               # "düşük" sarısı beyazda kayboluyordu
]


@st.cache_data(show_spinner=False, max_entries=16)
def grafik_dosyasi(yol, degisme_zamani, yukseklik=None):
    """Repodaki grafik HTML'i, uygulamada gösterilecek hale getirilmiş olarak (dosya değişince yenilenir)."""
    from pathlib import Path
    return grafik_html(Path(yol).read_text(encoding="utf-8"), yukseklik=yukseklik)


def grafik_goster(yol, yukseklik=980, tuval=None):
    """Grafik dosyasını gösterir; dosya yoksa bilgi yazar."""
    import streamlit.components.v1 as components
    if not yol.exists():
        st.caption(f"`{yol.name}` henüz üretilmedi.")
        return
    components.html(grafik_dosyasi(str(yol), yol.stat().st_mtime, tuval), height=yukseklik, scrolling=tuval is None)


def grafik_secici(secenekler, anahtar):
    """Sekme yerine seçici: yalnızca seçili grafik çizilir (her grafik ~750 KB, hepsini birden
    göndermek her adım geçişini yavaşlatıyordu)."""
    return st.segmented_control("Grafik", secenekler, default=secenekler[0], key=anahtar,
                                label_visibility="collapsed") or secenekler[0]


def grafik_html(metin, acik=True, yukseklik=None):
    """pyvis HTML'ini uygulamada göstermeye hazırlar (dosyaya yazılmaz): açık tema renkleri,
    istenirse tuval yüksekliği ve sekme içinde doğru sığdırma betiği."""
    if acik:
        for eski, yeni in _ACIK_RENKLER:
            metin = metin.replace(eski, yeni)
    if yukseklik:
        metin = metin.replace("height: 900px", f"height: {yukseklik}px")
    return metin.replace("</body>", _SIGDIR + "</body>") if "</body>" in metin else metin + _SIGDIR
