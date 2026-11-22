"""6. adım: önlem seçimi ve uygulama öncesi senaryo.

Ekibin dondurulmuş sonuçları üzerinde çalışır (ai/residual_risk.csv, graph/paths.json):
"şu önlemleri alırsak kalan risk ne olur, hangi yollar kapanır?" Hesap ai/onlem_secimi.py
ile aynı motordan gelir; lab'a hiçbir şey uygulanmaz, istek gönderilmez.
"""

import importlib.util
import math

import pandas as pd
import streamlit as st

from config import AI_DIR

KESINTI_ADI = {"yok": "yok", "dusuk": "düşük", "var": "var"}
TUR_ADI = {"yama": "Paket yaması", "kod": "Kod düzeltmesi", "yapilandirma": "Yapılandırma"}
HEDEF_ADI = {"node_target_admin": "Yönetici erişimi", "node_target_rce": "Kod çalıştırma",
             "node_target_account_takeover": "Hesap ele geçirme", "node_target_leak": "Veri sızıntısı",
             "node_target_dos": "Hizmet kesintisi"}


@st.cache_resource(show_spinner=False)
def _motor():
    spec = importlib.util.spec_from_file_location("onlem_secimi", AI_DIR / "onlem_secimi.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, mod.Model()


@st.cache_data(show_spinner=False)
def _en_iyi(butce, guven, kesintisiz):
    _, m = _motor()
    return m.en_iyi(butce, guven, kesintisiz)


def _yuzde(once, sonra):
    return f"-%{(1 - sonra / once) * 100:.1f}" if once else ""


def render():
    st.header("6. Önlem seçimi")
    st.markdown("**Sınırlı eforla riski en çok hangi önlemler azaltır?**")
    st.caption("Aday önlemler (paket yamaları, kod düzeltmeleri, yapılandırma) henüz uygulanmadı. "
               "Kalan risk, mevcut kontrollerin (WAF, sanal yamalar, IDS, IAM, segmentasyon) üzerine "
               "eklenerek hesaplanır. Lab'a hiçbir şey uygulanmaz.")
    try:
        mod, m = _motor()
    except Exception as e:  # noqa: BLE001 - arayüzde anlaşılır mesaj
        st.error(f"Önlem modeli yüklenemedi: {e}")
        return
    taban = m.degerlendir(m.mevcut)

    with st.container(border=True):
        c1, c2, c3 = st.columns([2, 1.3, 1.3])
        toplam = int(sum(o["efor_saat"] for o in m.katalog))
        butce = c1.slider("Efor bütçesi (saat)", 0, toplam, min(16, toplam))
        kesintisiz = c2.checkbox("Yalnızca kesinti gerektirmeyenler",
                                 help="Hizmet kesintisi gerektiren önlemler (yeniden dağıtımda oturum "
                                      "düşmesi, imaj değişimi) dışarıda bırakılır.")
        test = c3.toggle("Önlemler test edilmiş say", value=False,
                         help="Kapalı: plan aşaması, etkinlik gerekçeye dayalı (engeller = 0.63). "
                              "Açık: uygulanıp test edildiği varsayılır (engeller = 0.9), yollar kesilebilir.")
    guven = "test" if test else "gerekce"

    with st.spinner("Bütçeye sığan bütün bileşimler deneniyor..."):
        oneri = _en_iyi(butce, guven, kesintisiz)

    # Öneri değişince seçim kutusu öneriyle yeniden doldurulur; kullanıcı sonra değiştirebilir.
    anahtar = (butce, guven, kesintisiz)
    if st.session_state.get("onlem_anahtar") != anahtar:
        st.session_state["onlem_anahtar"] = anahtar
        st.session_state["onlem_secim"] = oneri["onlemler"]

    ad = {o["onlem_id"]: f"{o['onlem_id']} · {o['ad']}" for o in m.katalog}
    secim = st.multiselect("Uygulanacak önlemler (en iyi bileşim önerildi, değiştirebilirsiniz)",
                           [o["onlem_id"] for o in m.katalog], key="onlem_secim", format_func=ad.get)
    s = m.senaryo(secim, guven)

    if s["efor_saat"] > butce:
        st.warning(f"Seçim bütçeyi aşıyor: {s['efor_saat']:.0f} saat > {butce} saat.")
    elif sorted(secim) != sorted(oneri["onlemler"]) and s["yol_riski"] > oneri["yol_riski"] + 1e-6:
        st.info(f"Bu bütçede en iyi bileşim kalan yol riskini {oneri['yol_riski']:.2f}'e indiriyor "
                f"({', '.join(oneri['onlemler']) or 'önlem yok'}).")

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Kalan yol riski", f"{s['yol_riski']:.2f}", _yuzde(taban["yol_riski"], s["yol_riski"]),
              delta_color="inverse", help="Kritik varlıklara giden 36 yolun toplam riski.")
    k2.metric("Kalan zafiyet riski", f"{s['zafiyet_riski']:.2f}",
              _yuzde(taban["zafiyet_riski"], s["zafiyet_riski"]), delta_color="inverse")
    kes0, kes1 = taban["yol_durum"].get("kesildi", 0), s["yol_durum"].get("kesildi", 0)
    k3.metric("Kesilen yol", f"{kes1} / {len(m.yollar)}", f"+{kes1 - kes0}" if kes1 > kes0 else None)
    k4.metric("Efor", f"{s['efor_saat']:.0f} / {butce} saat")
    k4.caption("Hizmet kesintisi gerektiren önlem var." if "var" in s["kesinti"] else "Hizmet kesintisi gerekmiyor.")
    st.caption(f"Önlemlerden önce (mevcut kontroller açık): yol riski {taban['yol_riski']:.2f}, "
               f"zafiyet riski {taban['zafiyet_riski']:.2f}, {kes0} yol kesik.")

    sol, sag = st.columns([1.15, 1])
    with sol:
        st.subheader("Seçilen önlemler")
        if secim:
            satirlar = []
            for o in m.katalog:
                if o["onlem_id"] not in secim:
                    continue
                tek_s = m.senaryo([o["onlem_id"]], guven)
                satirlar.append({"Önlem": ad[o["onlem_id"]], "Tür": TUR_ADI.get(o["tur"], o["tur"]),
                                 "Zafiyetler": ", ".join(o["hedefler"]), "Efor (sa)": o["efor_saat"],
                                 "Kesinti": KESINTI_ADI[o["kesinti"]],
                                 "Tek başına yol riski düşüşü": round(taban["yol_riski"] - tek_s["yol_riski"], 2)})
            st.dataframe(pd.DataFrame(satirlar), hide_index=True, width="stretch")
            with st.expander("Gerekçeler"):
                for o in m.katalog:
                    if o["onlem_id"] in secim:
                        st.markdown(f"**{ad[o['onlem_id']]}**: {o['gerekce']}")
        else:
            st.caption("Önlem seçilmedi.")
    with sag:
        st.subheader("Kritik varlıklara göre")
        hedef = []
        for h, b in taban["hedef"].items():
            y = s["hedef"][h]
            hedef.append({"Hedef": HEDEF_ADI.get(h, h), "Yol riski (önce)": round(b["risk"], 2),
                          "Yol riski (sonra)": round(y["risk"], 2),
                          "Kesik / zayıf / açık": f"{y['kesildi']} / {y['zayifladi']} / {y['acik']}"})
        st.dataframe(pd.DataFrame(hedef).sort_values("Yol riski (sonra)", ascending=False),
                     hide_index=True, width="stretch")

    st.subheader("Yollar")
    taban_etk, yollar = m.mevcut, []
    for y in m.yollar:
        e0 = [taban_etk.get(v, 0.0) for v in y["zafiyetler"]]
        e1 = [s["etkinlik"].get(v, 0.0) for v in y["zafiyetler"]]
        r0 = y["C"] * math.prod(p * (1 - e) for p, e in zip(y["P"], e0))
        r1 = y["C"] * math.prod(p * (1 - e) for p, e in zip(y["P"], e1))
        durum = "kesildi" if any(x >= mod.KESILDI_ESIK for x in e1) else ("zayıfladı" if any(x > 0 for x in e1) else "açık")
        yollar.append({"Yol": " → ".join(n.replace("node_entry_", "giriş:").replace("node_target_", "hedef:")
                                         for n in y["yol"]),
                       "Önce": round(r0, 2), "Sonra": round(r1, 2), "Durum": durum,
                       "Değişti": "evet" if r1 < r0 - 1e-6 else ""})
    df = pd.DataFrame(yollar).sort_values(["Sonra", "Önce"], ascending=False)
    yalniz = st.checkbox("Yalnızca bu önlemlerle değişen yollar", value=True)
    st.dataframe(df[df["Değişti"] == "evet"] if yalniz else df, hide_index=True, width="stretch")

    with st.expander("Bütçeye göre kalan yol riski (ekibin raporundaki eğri)"):
        png = AI_DIR.parent / "report" / "img" / "onlem-butce.png"
        if png.exists():
            st.image(str(png), width="stretch")
            st.caption("`python ai/onlem_secimi.py` ile üretilir (plan aşaması, gerekçe dayanağı). "
                       "Ayrıntı: `docs/onlem-secimi.md`.")
        else:
            st.caption("Eğri henüz üretilmedi: `python ai/onlem_secimi.py`.")
