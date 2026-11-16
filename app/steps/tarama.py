"""2. adım: taramaların çalıştırılması veya ham dosyaların yüklenmesi."""

import datetime

import streamlit as st

from config import TARGETS
from pipeline import runs, scans
from steps.ortak import durumlar

CANLI, REPO, YUKLE, ATLA = "Canlı topla", "Repodaki dosya", "Dosya yükle", "Atla"
LOG_SATIR = 15


def _varsayilan(kaynak, lab_hazir):
    if lab_hazir:
        return CANLI
    return REPO if scans.repo_dosyasi(kaynak).exists() else ATLA


def _calistir(kaynak, yontem, target, raw_dir, yuklenen):
    if yontem == REPO:
        return scans.yukle_repodan(kaynak, raw_dir)
    if yontem == YUKLE:
        if yuklenen is None:
            return scans.Sonuc(False, "Dosya seçilmedi.")
        return scans.yukle_bayttan(kaynak, raw_dir, yuklenen.getvalue())

    # Canlı: çıktı satırlarını kayan bir günlükte göster
    satirlar = []
    with st.status(f"{scans.KAYNAK_ADLARI[kaynak]} çalışıyor...", expanded=True) as durum:
        kutu = st.empty()

        def on_line(line):
            if line:
                satirlar.append(line)
                kutu.code("\n".join(satirlar[-LOG_SATIR:]), language=None)

        sonuc = scans.CANLI[kaynak](target, raw_dir, on_line)
        durum.update(label=f"{scans.KAYNAK_ADLARI[kaynak]}: {sonuc.mesaj}",
                     state="complete" if sonuc.ok else "error", expanded=not sonuc.ok)
    return sonuc


def render():
    run_id = st.session_state["run_id"]
    target = TARGETS[st.session_state["target"]]
    raw_dir = runs.run_dir(run_id) / "raw"
    meta = runs.load_meta(run_id)
    tarama = meta["steps"].get("tarama", {})

    st.header("2. Tarama")
    st.caption("Her kaynak için yöntemi seçin. Canlı toplama lab ortamının çalışmasını "
               "gerektirir; ZAP baseline pasif bir taramadır, hedefe saldırı isteği göndermez.")

    docker, konteyner = durumlar(target["konteyner"])
    lab_hazir = docker.ok and konteyner.ok
    if not lab_hazir:
        st.warning(f"Lab ortamı hazır değil: {konteyner.mesaj if docker.ok else docker.mesaj} "
                   "Canlı toplama seçilen kaynaklar başarısız olur.")

    secimler, yuklenenler = {}, {}
    for kaynak in scans.RAW_FILES:
        with st.container(border=True):
            ust1, ust2 = st.columns([3, 2])
            with ust1:
                st.markdown(f"**{scans.KAYNAK_ADLARI[kaynak]}**")
                onceki = tarama.get(kaynak)
                if onceki and onceki["ok"]:
                    ozet = ", ".join(f"{k}: {v}" for k, v in onceki["ozet"].items())
                    st.caption(f"Bu çalıştırmada toplandı ({onceki['yontem']}): {ozet}")
            secenekler = [CANLI, REPO, YUKLE, ATLA]
            with ust2:
                secimler[kaynak] = st.radio(
                    "Yöntem", secenekler, key=f"yontem_{kaynak}", horizontal=True,
                    index=secenekler.index(_varsayilan(kaynak, lab_hazir)),
                    label_visibility="collapsed",
                )
            if secimler[kaynak] == YUKLE:
                yuklenenler[kaynak] = st.file_uploader(
                    f"{scans.RAW_FILES[kaynak]} seçin", type=["json"], key=f"dosya_{kaynak}")
            if kaynak == "trivy" and secimler[kaynak] == CANLI:
                st.caption("İlk çalıştırmada Trivy zafiyet veritabanını indirir, birkaç dakika sürebilir.")

    if st.button("Başlat", type="primary"):
        for kaynak, yontem in secimler.items():
            if yontem == ATLA:
                continue
            sonuc = _calistir(kaynak, yontem, target, raw_dir, yuklenenler.get(kaynak))
            tarama[kaynak] = {
                "yontem": yontem, "ok": sonuc.ok, "mesaj": sonuc.mesaj,
                "sure_sn": round(sonuc.sure, 1), "ozet": sonuc.ozet,
                "zaman": datetime.datetime.now().isoformat(timespec="seconds"),
            }
            meta["steps"]["tarama"] = tarama
            runs.save_meta(run_id, meta)   # her kaynaktan sonra kaydet, yarıda kalırsa kaybolmasın

    if tarama:
        st.subheader("Bu çalıştırmanın ham verisi")
        st.dataframe(
            [{
                "Kaynak": scans.KAYNAK_ADLARI[k],
                "Yöntem": v["yontem"],
                "Durum": "✅" if v["ok"] else "❌",
                "Süre (sn)": v["sure_sn"],
                "Özet": ", ".join(f"{a}: {b}" for a, b in v["ozet"].items()) or v["mesaj"],
            } for k, v in tarama.items()],
            hide_index=True,
        )
        if any(v["ok"] for v in tarama.values()):
            st.success("Ham veri hazır. Sol menüden 3. adıma geçin.")
