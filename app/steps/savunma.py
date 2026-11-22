"""5. adım: lab'ın WAF doğrulama testinin çalıştırılması ve savunma panosuna geçiş."""

import datetime

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from config import GRAFANA_PANO, GRAFANA_URL, GRAPH_DIR, TARGETS
from pipeline import ai_skor, runs, saldiri_testi
from steps import ortak, tema


def render():
    run_id = st.session_state["run_id"]
    meta = runs.load_meta(run_id)
    tema.baslik("Adım 5", "Savunma testi", "Kontroller bu zafiyetleri yakalıyor mu?")
    st.caption("Lab'ın savunma doğrulama testini (`defense/test-waf.sh`) çalıştırır: grafikteki "
               "zafiyetlere (SQLi, XSS, rol atama, XXE, CSRF, açık yönlendirme) ait test istekleri, "
               "güvenlik başlıkları, hata sayfası ve hız sınırı kontrolleri yalnızca kendi lab "
               "hedefimize gönderilir. Her saldırının yanında aynı uç noktaya zararsız bir kontrol "
               "isteği vardır (yanlış pozitif olmadığını gösterir). Test en sonda hız sınırını "
               "denediği için ardından ~2 dakika giriş istekleri 429 alabilir.")
    target = TARGETS[st.session_state["target"]]
    docker, konteyner = ortak.durumlar(target["konteyner"])
    hazir, neden = saldiri_testi.hazir_mi()
    if not (docker.ok and konteyner.ok):
        hazir, neden = False, "Lab ortamı çalışmıyor; test canlı hedef gerektirir."

    c1, c2 = st.columns(2)
    calistir = c1.button("Saldırı testlerini çalıştır", disabled=not hazir, use_container_width=True)
    pano = ortak.grafana(GRAFANA_URL)
    c2.link_button("Sonuçları savunma panosunda gör ↗", GRAFANA_PANO, disabled=not pano.ok,
                   use_container_width=True)
    if not hazir:
        st.caption(neden)

    if calistir:
        with st.spinner("Test istekleri gönderiliyor..."):
            sonuc = saldiri_testi.calistir(target)
        meta["steps"]["saldiri_testi"] = {
            "ok": sonuc.ok, "mesaj": sonuc.mesaj, "satirlar": sonuc.satirlar, "sure_sn": round(sonuc.sure, 1),
            "zaman": datetime.datetime.now().isoformat(timespec="seconds")}
        runs.save_meta(run_id, meta)
        if not sonuc.satirlar:
            st.error(sonuc.mesaj)
            if sonuc.cikti:
                st.code(sonuc.cikti, language=None)
            return

    son = meta["steps"].get("saldiri_testi")
    if son and son.get("satirlar"):
        (st.success if son["ok"] else st.warning)(f"{son['mesaj']} ({son['zaman']})")
        # Test edilen zafiyetlerin bu çalıştırmadaki adı ve AI skoru (grafikle bağlantı)
        rdir = runs.run_dir(run_id)
        bilgi = {r["Kayıt"]: r for r in ai_skor.tablo(rdir)} if (rdir / "inventory.csv").exists() else {}
        df = pd.DataFrame(son["satirlar"])
        for sutun in ("HTTP", "Beklenen"):   # kontrol satırlarında boş
            if sutun in df:
                df[sutun] = df[sutun].astype("Int64")
        df.insert(3, "Zafiyet adı", df["Zafiyet"].map(lambda v: bilgi.get(v, {}).get("Ad", "")))
        df.insert(4, "AI skoru", df["Zafiyet"].map(lambda v: bilgi.get(v, {}).get("AI skoru")))
        st.dataframe(df, hide_index=True, use_container_width=True)
        if pano.ok:
            st.caption("Panoda olayların görünmesi 5-10 saniye sürebilir; zaman aralığını "
                       "\"Son 15 dakika\" seçin.")

    _once_sonra_grafik()


def _once_sonra_grafik():
    """Ekibin sonuç dosyalarından kontroller öncesi ve sonrası grafik (graph/attack_graph_v2.html,
    graph/attack_graph_after.html). İki grafik aynı yerleşimde çizildiği için sekmeler arasında
    geçince yalnızca kenar ve düğüm durumları değişir."""
    once, sonra = GRAPH_DIR / "attack_graph_v2.html", GRAPH_DIR / "attack_graph_after.html"
    st.divider()
    st.subheader("Kontroller öncesi ve sonrası grafik")
    if not (once.exists() and sonra.exists()):
        st.caption("Grafikler henüz üretilmedi: `python graph/visualize_graph.py` ve "
                   "`python graph/visualize_graph.py --after`.")
        return
    st.caption("Ekibin dondurulmuş sonuçları (testle doğrulanmış kontroller). Sonra grafiğinde kesilen "
               "kenarlar gri ve kesikli, zayıflayanlar turuncu; düğüm rengi kontrol sonrası risk. "
               "İki grafik aynı yerleşimde: sekme değiştirince yalnızca durumlar değişir.")
    t1, t2 = st.tabs(["Kontroller öncesi", "Kontroller sonrası"])
    with t1:
        components.html(ortak.grafik_html(once.read_text(encoding="utf-8")), height=980, scrolling=True)
    with t2:
        components.html(ortak.grafik_html(sonra.read_text(encoding="utf-8")), height=980, scrolling=True)
