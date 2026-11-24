"""2. adım: taramaların çalıştırılması veya ham dosyaların yüklenmesi."""

import datetime

import streamlit as st

from config import TARGETS
from pipeline import runs, scans
from steps import isler, tema
from steps.ortak import durumlar

CANLI, REPO, YUKLE, ATLA = "Canlı topla", "Repodaki dosya", "Dosya yükle", "Atla"
LOG_SATIR = 15


def _varsayilan(kaynak, lab_hazir):
    if lab_hazir:
        return CANLI
    return REPO if scans.repo_dosyasi(kaynak).exists() else ATLA


def _calistir(kaynak, yontem, target, raw_dir, yuklenen, is_):
    if yontem == REPO:
        return scans.yukle_repodan(kaynak, raw_dir)
    if yontem == YUKLE:
        if yuklenen is None:
            return scans.Sonuc(False, "Dosya seçilmedi.")
        return scans.yukle_bayttan(kaynak, raw_dir, yuklenen)

    # Canlı: çıktı satırları işin günlüğüne yazılır, sayfa son satırları gösterir
    def on_line(line):
        is_.satir(line)
    on_line.iptal = is_.iptal_mi
    return scans.CANLI[kaynak](target, raw_dir, on_line)


def _tarama_is(is_, run_id, secimler, target, raw_dir, yuklenenler):
    """Arka planda: seçilen kaynakları sırayla toplar, her kaynaktan sonra çalıştırmaya yazar."""
    sirali = [(k, y) for k, y in secimler.items() if y != ATLA]
    sonuclar = {}
    for n, (kaynak, yontem) in enumerate(sirali):
        if is_.iptal_mi():
            break
        is_.ilerle(n / len(sirali), f"{scans.KAYNAK_ADLARI[kaynak]} ({yontem.lower()})")
        is_.satir(f"--- {scans.KAYNAK_ADLARI[kaynak]} ---")
        sonuc = _calistir(kaynak, yontem, target, raw_dir, yuklenenler.get(kaynak), is_)
        is_.satir(f"{scans.KAYNAK_ADLARI[kaynak]}: {sonuc.mesaj}")
        sonuclar[kaynak] = sonuc
        meta = runs.load_meta(run_id)     # en güncelini al: o arada başka adımda kaydedilmiş olabilir
        meta["steps"].setdefault("tarama", {})[kaynak] = {
            "yontem": yontem, "ok": sonuc.ok, "mesaj": sonuc.mesaj,
            "sure_sn": round(sonuc.sure, 1), "ozet": sonuc.ozet,
            "zaman": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        runs.save_meta(run_id, meta)   # her kaynaktan sonra kaydet, yarıda kalırsa kaybolmasın
    return sonuclar


def render():
    run_id = st.session_state["run_id"]
    target = TARGETS[st.session_state["target"]]
    raw_dir = runs.run_dir(run_id) / "raw"
    meta = runs.load_meta(run_id)
    tarama = meta["steps"].get("tarama", {})

    tema.baslik("Adım 2", "Tarama", "Hedefte hangi ham bulgular var?")
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
                st.session_state.setdefault(f"yontem_{kaynak}", _varsayilan(kaynak, lab_hazir))
                secimler[kaynak] = st.radio(
                    "Yöntem", secenekler, key=f"yontem_{kaynak}", horizontal=True,
                    label_visibility="collapsed",
                )
            if secimler[kaynak] == YUKLE:
                yuklenenler[kaynak] = st.file_uploader(
                    f"{scans.RAW_FILES[kaynak]} seçin", type=["json"], key=f"dosya_{kaynak}")
            if kaynak == "trivy" and secimler[kaynak] == CANLI:
                st.caption("İlk çalıştırmada Trivy zafiyet veritabanını indirir, birkaç dakika sürebilir.")

    anahtar = f"tarama_{run_id}"
    suruyor = isler.ilerleme(anahtar, gunluk_satir=LOG_SATIR)
    bitti = isler.sonuc(anahtar)
    if bitti:
        if bitti.durum == isler.HATA:
            st.error(f"Tarama yarıda kaldı: {bitti.hata}")
        else:
            for kaynak, s in (bitti.sonuc or {}).items():
                (st.success if s.ok else st.error)(f"{scans.KAYNAK_ADLARI[kaynak]}: {s.mesaj}")
            if bitti.durum == isler.IPTAL:
                st.warning("Tarama iptal edildi.")
            if any(not s.ok for s in (bitti.sonuc or {}).values()) and bitti.gunluk:
                with st.expander("Günlük"):
                    st.code("\n".join(bitti.gunluk[-60:]), language=None)
    if st.button("Başlat", type="primary", disabled=suruyor):
        yuk = {k: (f.getvalue() if f is not None else None) for k, f in yuklenenler.items()}
        isler.baslat(anahtar, f"Tarama ({run_id})",
                     lambda is_: _tarama_is(is_, run_id, dict(secimler), target, raw_dir, yuk))
        st.rerun()

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
