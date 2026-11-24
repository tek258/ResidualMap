"""Yan menüdeki "Ortamı başlat" düğmesi ve penceresi.

Uygulamanın arkada ihtiyaç duyduğu dört bileşenin durumunu gösterir ve tek tıkla sırayla
başlatır: Docker Desktop -> lab (defense/, savunma panosu dahil) -> Ollama + model.
Komutlar app/pipeline/ortam.py'de sabittir.
"""

import time

import streamlit as st

from config import GRAFANA_URL, TARGETS
from pipeline import docker_check, ortam
from steps import ortak

HEDEF_URL = TARGETS["juice-shop"]["tarayici_url"]


def _model_adi():
    from pipeline import ai_skor
    return ai_skor.model_modulu().MODEL_NAME


@st.cache_data(ttl=60, show_spinner=False)
def ozet():
    """{bileşen: (ok, açıklama)}. Docker kapalıyken yalnızca bir `docker info` çağrısı yapılır."""
    d = {}
    if not ortam.docker_kurulu():
        d["docker"] = (False, "Kurulu değil (KURULUM.md)")
    elif not ortam.docker_hazir():
        d["docker"] = (False, "Kapalı")
    else:
        d["docker"] = (True, "Çalışıyor")
    lab = ortam.lab_durumu() if d["docker"][0] else None
    if lab is None:
        d["lab"] = (False, "Docker kapalı")
    else:
        calisan = sorted(s for s, durum in lab.items() if durum == "running")
        beklenen = len(ortam.lab_servisleri()) or len(lab)
        acik = ortam.http_hazir(HEDEF_URL)
        if acik and len(calisan) >= beklenen:
            d["lab"] = (True, f"{len(calisan)}/{beklenen} servis çalışıyor")
        else:
            d["lab"] = (False, f"{len(calisan)}/{beklenen} servis çalışıyor"
                               + ("" if acik else ", Juice Shop yanıt vermiyor"))
    pano = ortak.grafana(GRAFANA_URL)
    d["pano"] = (pano.ok, "Açık" if pano.ok else "Kapalı")
    ok, _, model = ortak.ollama()
    if ok:
        d["ai"] = (True, f"Açık, {model}")
    elif ortam.ollama_calisiyor():
        d["ai"] = (False, f"Açık, {model} yüklü değil")
    else:
        d["ai"] = (False, "Kapalı (isteğe bağlı)" if ortam._ollama_yolu() or ortam.SISTEM == "Darwin"
                   else "Kurulu değil (isteğe bağlı)")
    return d


ADLAR = {"docker": "Docker Desktop", "lab": "Lab ortamı (Juice Shop, WAF, IDS, IAM)",
         "pano": "Savunma panosu (Grafana)", "ai": "Yerel AI (Ollama + model)"}


def _onbellegi_temizle():
    ozet.clear()
    ortak.durumlar.clear()
    ortak.grafana.clear()
    ortak.ollama.clear()


def yan_menu():
    """Yan menüdeki kısa durum satırı ve düğme."""
    d = ozet()
    hazir = all(d[k][0] for k in ("docker", "lab", "pano"))
    isaret = " ".join(("🟢" if d[k][0] else "⚪") for k in ADLAR)
    st.caption(f"Ortam: {isaret}  " + ("hazır" if hazir and d["ai"][0] else
                                       "AI kapalı" if hazir else "kapalı"))
    if st.button("Ortamı başlat" if not hazir else "Ortam durumu", icon=":material/power_settings_new:",
                 use_container_width=True, type="primary" if not hazir else "secondary"):
        pencere()


def _durum_tablosu(d):
    for k, ad in ADLAR.items():
        ok, aciklama = d[k]
        st.markdown(f"{'🟢' if ok else '⚪'} **{ad}**  \n<span style='color:#6b7387'>{aciklama}</span>",
                    unsafe_allow_html=True)


def _hepsini_baslat():
    """Bileşenleri sırayla başlatır. Dönüş: [(ok, mesaj)]."""
    sonuc = []
    with st.status("Ortam başlatılıyor…", expanded=True) as durum:
        # 1. Docker
        st.write("**1/4 Docker Desktop**")
        if not ortam.docker_kurulu():
            durum.update(label="Docker kurulu değil", state="error")
            return [(False, "Docker kurulu değil. İlk kurulum: KURULUM.md")]
        if not ortam.docker_hazir():
            s = ortam.docker_desktop_baslat()
            if not s.ok:
                durum.update(label="Docker başlatılamadı", state="error")
                return [(False, s.mesaj)]
            st.write("Docker Desktop açılıyor, motorun hazır olması bekleniyor (en fazla 3 dk)…")
            if not ortam._bekle(ortam.docker_hazir, 180, aralik=4):
                durum.update(label="Docker hazır olmadı", state="error")
                return [(False, "Docker 3 dakikada hazır olmadı. Docker Desktop penceresini kontrol edin.")]
        sonuc.append((True, "Docker çalışıyor."))

        # 2. Lab
        st.write("**2/4 Lab ortamı** (`docker compose --profile siem up -d`, ilk seferde imajlar iner)")
        satir = st.empty()
        s = ortam.lab_baslat(lambda m: satir.code(m[-160:], language=None))
        satir.empty()
        if not s.ok:
            durum.update(label="Lab başlatılamadı", state="error")
            return sonuc + [(False, s.mesaj)]
        st.write("Juice Shop'un yanıt vermesi bekleniyor…")
        hedef_ok = ortam._bekle(lambda: ortam.http_hazir(HEDEF_URL), 120)
        sonuc.append((hedef_ok, "Lab çalışıyor, Juice Shop yanıt veriyor." if hedef_ok else
                      "Lab konteynerleri başladı ama Juice Shop 2 dk içinde yanıt vermedi."))

        # 3. Pano
        st.write("**3/4 Savunma panosu**")
        pano_ok = ortam._bekle(lambda: docker_check.grafana_durumu(GRAFANA_URL).ok, 90)
        sonuc.append((pano_ok, "Savunma panosu açık." if pano_ok else
                      "Grafana 90 sn içinde açılmadı; birazdan durumu yenileyin."))

        # 4. Ollama (isteğe bağlı: hata durumu kırmızı değil, uyarı)
        st.write("**4/4 Yerel AI** (isteğe bağlı)")
        model = _model_adi()
        if not ortam.ollama_calisiyor():
            s = ortam.ollama_baslat()
            if not s.ok:
                sonuc.append((None, s.mesaj))
            elif not ortam._bekle(ortam.ollama_calisiyor, 40, aralik=2):
                sonuc.append((None, "Ollama başlatıldı ama yanıt vermedi."))
        if ortam.ollama_calisiyor():
            if not ortam.model_yuklu(model):
                st.write(f"`{model}` indiriliyor (~4.7 GB, yalnızca ilk sefer)…")
                cubuk = st.progress(0.0)
                s = ortam.model_indir(model, lambda o, m: cubuk.progress(o or 0.0, text=m))
                cubuk.empty()
                sonuc.append((True if s.ok else None, s.mesaj))
            if ortam.model_yuklu(model):
                st.write("Model belleğe yükleniyor (ilk AI çağrısı beklemesin diye)…")
                s = ortam.model_isit(model)
                sonuc.append((True if s.ok else None, s.mesaj))
        hata = any(ok is False for ok, _ in sonuc)
        durum.update(label="Ortam hazır" if not hata else "Ortam kısmen hazır",
                     state="complete" if not hata else "error", expanded=False)
    return sonuc


@st.dialog("Ortam", width="large")
def pencere():
    st.caption("Uygulamanın arkada ihtiyaç duyduğu bileşenler. Yalnızca bu makinedeki yerel lab "
               "başlatılır; komutlar sabittir. İlk kurulum (Docker Desktop, WSL, Ollama): KURULUM.md")
    sonuc = st.session_state.pop("ortam_sonuc", None)
    d = ozet()
    _durum_tablosu(d)
    if sonuc:
        for ok, mesaj in sonuc:
            (st.success if ok else st.warning if ok is None else st.error)(mesaj)

    st.write("")
    c1, c2, c3, c4 = st.columns(4)
    if c1.button("Hepsini başlat", type="primary", icon=":material/play_arrow:", use_container_width=True,
                 disabled=all(ok for ok, _ in d.values())):
        t0 = time.time()
        sonuc = _hepsini_baslat()
        sonuc.append((True, f"Toplam süre: {time.time() - t0:.0f} sn."))
        st.session_state["ortam_sonuc"] = sonuc
        _onbellegi_temizle()
        st.rerun(scope="fragment")
    if c2.button("Lab'ı durdur", icon=":material/stop:", use_container_width=True, disabled=not d["lab"][0]
                 and not d["pano"][0]):
        with st.spinner("Lab durduruluyor…"):
            s = ortam.lab_durdur()
        st.session_state["ortam_sonuc"] = [(s.ok, s.mesaj + (" Docker Desktop ve Ollama açık bırakıldı."
                                                              if s.ok else ""))]
        _onbellegi_temizle()
        st.rerun(scope="fragment")
    if c3.button("Durumu yenile", icon=":material/refresh:", use_container_width=True):
        _onbellegi_temizle()
        st.rerun(scope="fragment")
    if c4.button("Kapat", use_container_width=True):
        st.rerun()   # bütün sayfayı yeniler: yan menüdeki durum da güncellenir
