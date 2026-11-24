"""Yan menüde "Çalıştırma raporu": bütün sonuçları tek HTML dosyasında indirme."""

import streamlit as st

from pipeline import rapor


def _onlem_plani():
    """6. adımdaki seçim (adım hiç açılmadıysa 16 saatlik en iyi plan) ve varsa AI açıklaması."""
    from steps import onlem
    mod, m = onlem._motor()
    butce = st.session_state.get("onlem_butce", 16)
    guven = "test" if st.session_state.get("onlem_test") else "gerekce"
    secim = st.session_state.get("onlem_secim_son")
    if secim is None:
        secim = onlem._en_iyi(butce, guven, bool(st.session_state.get("onlem_kesintisiz")))["onlemler"]
    taban, s = m.degerlendir(m.mevcut), m.senaryo(secim, guven)
    onlemler = []
    for o in m.katalog:
        if o["onlem_id"] in secim:
            tek = m.senaryo([o["onlem_id"]], guven)
            onlemler.append({"ad": f"{o['onlem_id']} · {o['ad']}", "tur": onlem.TUR_ADI.get(o["tur"], o["tur"]),
                             "zafiyetler": ", ".join(o["hedefler"]), "efor": o["efor_saat"],
                             "kesinti": onlem.KESINTI_ADI[o["kesinti"]],
                             "dusus": round(taban["yol_riski"] - tek["yol_riski"], 2)})
    aciklama = st.session_state.get(("plan_aciklama", tuple(sorted(secim)), guven, butce))
    return {
        "butce": butce, "efor": s["efor_saat"], "toplam_yol": len(m.yollar),
        "dayanak": "plan aşaması (etkinlik gerekçeye dayalı)" if guven == "gerekce" else "önlemler test edilmiş varsayımı",
        "once": {"yol": taban["yol_riski"], "kesik": taban["yol_durum"].get("kesildi", 0)},
        "sonra": {"yol": s["yol_riski"], "kesik": s["yol_durum"].get("kesildi", 0)},
        "dusus_yuzde": (1 - s["yol_riski"] / taban["yol_riski"]) * 100 if taban["yol_riski"] else 0,
        "onlemler": onlemler,
        "aciklama": aciklama[:2] if aciklama and aciklama[0] else None,
    }


def yan_menu():
    run_id = st.session_state.get("run_id")
    if st.button("Çalıştırma raporu", icon=":material/description:", use_container_width=True,
                 disabled=not run_id, key="rapor_ac",
                 help="Bu çalıştırmanın bütün sonuçları tek bir HTML dosyasında: tarama, bulgular, AI skorları, "
                      "saldırı yolları, savunma testi, önlem planı ve AI izi."):
        pencere(run_id)


@st.dialog("Çalıştırma raporu", width="medium")
def pencere(run_id):
    st.caption("Bu çalıştırmanın sonuçları tek bir HTML dosyasında. Tarayıcıda açılır; PDF için tarayıcının "
               "\"Yazdır → PDF olarak kaydet\" seçeneği kullanılır. Önlem planı 6. adımdaki seçimden gelir "
               "(adım açılmadıysa 16 saatlik en iyi plan); plan AI ile açıklandıysa açıklama da eklenir.")
    grafik = st.checkbox("Etkileşimli saldırı grafiğini ekle (~1 MB, açılışta internet gerektirir)", value=True)
    try:
        plan = _onlem_plani()
    except Exception as e:  # noqa: BLE001 - plan olmadan da rapor üretilebilsin
        st.warning(f"Önlem planı eklenemedi: {e}")
        plan = None
    with st.spinner("Rapor hazırlanıyor…"):
        metin = rapor.olustur(run_id, plan, grafik_ekle=grafik)
    st.download_button("Raporu indir (HTML)", metin.encode("utf-8"), file_name=f"residualmap-rapor-{run_id}.html",
                       mime="text/html", type="primary", icon=":material/download:", use_container_width=True)
    if plan:
        st.caption(f"Plan: {len(plan['onlemler'])} önlem, {plan['butce']} saat bütçe"
                   + (", AI açıklaması dahil." if plan["aciklama"] else ". AI açıklaması yok (6. adımda \"Planı AI ile açıkla\")."))
