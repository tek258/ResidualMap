"""6. adım: önlem seçimi ve uygulama öncesi senaryo.

"Şu önlemleri alırsak kalan risk ne olur, hangi yollar kapanır?" Hesap ai/onlem_secimi.py ile
aynı motordan gelir; lab'a hiçbir şey uygulanmaz, istek gönderilmez. Açık bir çalıştırmanın
grafiği varsa o çalıştırmanın yolları ve zafiyetleriyle (pipeline/calisma_modeli.py), yoksa
ekibin dondurulmuş sonuçlarıyla (ai/residual_risk.csv, graph/paths.json) çalışır.
"""

import math

import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from config import AI_DIR, GRAPH_DIR
from pipeline import runs
from steps import isler, ortak, tema

KESINTI_ADI = {"yok": "yok", "dusuk": "düşük", "var": "var"}
TUR_ADI = {"yama": "Paket yaması", "kod": "Kod düzeltmesi", "yapilandirma": "Yapılandırma"}
HEDEF_ADI = {"node_target_admin": "Yönetici erişimi", "node_target_rce": "Kod çalıştırma",
             "node_target_account_takeover": "Hesap ele geçirme", "node_target_leak": "Veri sızıntısı",
             "node_target_dos": "Hizmet kesintisi"}


def model_anahtari():
    """Hangi modelin kullanılacağı: açık çalıştırmanın grafiği varsa (run_id, dosya zamanları),
    yoksa None (ekibin dondurulmuş sonuçları). Dosyalar değişince anahtar da değişir."""
    rid = st.session_state.get("run_id")
    if not rid:
        return None
    rdir = runs.run_dir(rid)
    dosyalar = [rdir / "inventory.csv", rdir / "graph" / "paths.json", rdir / "ai_skorlari.csv"]
    if not dosyalar[0].exists() or not dosyalar[1].exists():
        return None
    return (rid, *(f.stat().st_mtime if f.exists() else 0 for f in dosyalar))


@st.cache_resource(show_spinner=False, max_entries=4)
def _motor(anahtar=None):
    from pipeline import calisma_modeli
    if anahtar:
        return calisma_modeli.kur(runs.run_dir(anahtar[0]))
    mod = calisma_modeli.motor_modulu()
    return mod, mod.Model()


@st.cache_data(show_spinner=False, max_entries=32)
def _senaryo_html(secim, guven, anahtar=None, baslik="Seçilen önlemlerden sonra (senaryo)"):
    """Seçilen önlemlerden sonraki grafik (HTML metni). Geçici klasöre yazılır, repo değişmez."""
    from pipeline import calisma_modeli
    mod, m = _motor(anahtar)
    with tempfile.TemporaryDirectory() as d:
        if anahtar:
            yol = calisma_modeli.senaryo_grafigi(mod, m, runs.run_dir(anahtar[0]), list(secim), guven, d, baslik)
        else:
            yol = mod.senaryo_grafigi(m, list(secim), guven, d)
        return Path(yol).read_text(encoding="utf-8")


@st.cache_data(show_spinner=False)
def _en_iyi(butce, guven, kesintisiz, anahtar=None):
    _, m = _motor(anahtar)
    return m.en_iyi(butce, guven, kesintisiz)


def kaynak_notu(m, anahtar):
    """Hesabın hangi veriyle yapıldığı (6. ve 5. adım)."""
    if not anahtar:
        st.info("Açık bir çalıştırmanın grafiği yok: hesap ekibin dondurulmuş sonuçlarıyla (36 zafiyet, "
                "36 yol) yapılıyor. Kendi seçiminizle hesaplamak için 1-4. adımları tamamlayın.")
        return
    yeni_yol = sum(1 for y in m.yollar if any(v in set(m.eslenmemis) for v in y["zafiyetler"]))
    oto = [o for o in m.katalog if o.get("oto")]
    eklenen = sum(o.get("eklenen", 0) for o in m.katalog)
    st.info(f"Hesap bu çalıştırmanın grafiğiyle yapılıyor: {len(m.risk_before)} zafiyet, "
            f"{len(m.yollar) + m.risksiz_yol} yol"
            + (f" (bunların {m.risksiz_yol} tanesinde bir zafiyetin CVSS vektörü olmadığı için yol riski "
               f"hesaplanamıyor; bu yollar grafikte var, risk toplamına girmiyor)" if m.risksiz_yol else "")
            + ". Mevcut kontrollerin etkinliği ekibin eşlemesinden gelir"
            + (f"; eşlemesi olmayan {len(m.eslenmemis)} yeni zafiyet için 0 sayıldı ({yeni_yol} yolda)" if m.eslenmemis else "")
            + ". Önlemler: ekibin kataloğu"
            + (f" + {len(oto)} otomatik paket yükseltmesi" if oto else "")
            + (f" (katalogdaki önlemlere {eklenen} yeni CVE eklendi)" if eklenen else "") + "."
            + (" Önlem sayısı fazla olduğu için en iyi bileşim açgözlü seçimle bulunuyor (kesin değil)."
               if m.yontem == "açgözlü" else ""))
    if m.eslenmemis or oto:
        with st.expander("Yeni zafiyetler ve otomatik önlemler"):
            if oto:
                st.markdown("**Otomatik paket yükseltmeleri** (Trivy'deki düzeltilmiş sürümden; ekip değerlendirmedi)")
                st.dataframe(pd.DataFrame([{"Önlem": f"{o['onlem_id']} · {o['ad']}", "Zafiyetler": ", ".join(o["hedefler"]),
                                            "Efor (sa)": o["efor_saat"], "Gerekçe": o["gerekce"]} for o in oto]),
                             hide_index=True, width="stretch")
            if m.duzeltmesiz:
                st.caption(f"Düzeltilmiş sürümü olmayan {len(m.duzeltmesiz)} CVE için önlem önerilmedi: "
                           + ", ".join(m.duzeltmesiz[:20]) + (" …" if len(m.duzeltmesiz) > 20 else ""))
            if m.eslenmemis:
                st.caption(f"Kontrol eşlemesi olmayan (mevcut etkinlik 0) zafiyetler: "
                           + ", ".join(m.eslenmemis[:30]) + (" …" if len(m.eslenmemis) > 30 else ""))


def _yuzde(once, sonra):
    return f"-%{(1 - sonra / once) * 100:.1f}" if once else ""


def render():
    tema.baslik("Adım 6", "Önlem seçimi", "Sınırlı eforla riski en çok hangi önlemler azaltır?")
    st.caption("Aday önlemler (paket yamaları, kod düzeltmeleri, yapılandırma) henüz uygulanmadı. "
               "Kalan risk, mevcut kontrollerin (WAF, sanal yamalar, IDS, IAM, segmentasyon) üzerine "
               "eklenerek hesaplanır. Lab'a hiçbir şey uygulanmaz.")
    anahtar_m = model_anahtari()
    try:
        with st.spinner("Önlem modeli bu çalıştırmanın grafiğiyle kuruluyor..."):
            mod, m = _motor(anahtar_m)
    except Exception as e:  # noqa: BLE001 - arayüzde anlaşılır mesaj
        st.error(f"Önlem modeli yüklenemedi: {e}")
        return
    kaynak_notu(m, anahtar_m)
    taban = m.degerlendir(m.mevcut)

    with st.container(border=True):
        c1, c2, c3 = st.columns([2, 1.3, 1.3])
        toplam = int(sum(o["efor_saat"] for o in m.katalog))
        st.session_state.setdefault("onlem_butce", min(16, toplam))
        butce = c1.slider("Efor bütçesi (saat)", 0, toplam, key="onlem_butce")
        kesintisiz = c2.checkbox("Yalnızca kesinti gerektirmeyenler", key="onlem_kesintisiz",
                                 help="Hizmet kesintisi gerektiren önlemler (yeniden dağıtımda oturum "
                                      "düşmesi, imaj değişimi) dışarıda bırakılır.")
        test = c3.toggle("Önlemler test edilmiş say", key="onlem_test",
                         help="Kapalı: plan aşaması, etkinlik gerekçeye dayalı (engeller = 0.63). "
                              "Açık: uygulanıp test edildiği varsayılır (engeller = 0.9), yollar kesilebilir.")
    guven = "test" if test else "gerekce"

    with st.spinner("Bütçeye sığan bütün bileşimler deneniyor..." if getattr(m, "yontem", "kesin") == "kesin"
                    else "En iyi bileşim açgözlü seçimle aranıyor..."):
        oneri = _en_iyi(butce, guven, kesintisiz, anahtar_m)

    # Öneri değişince seçim kutusu öneriyle yeniden doldurulur; kullanıcı sonra değiştirebilir.
    anahtar = (butce, guven, kesintisiz, anahtar_m)
    gecerli = {o["onlem_id"] for o in m.katalog}
    if st.session_state.get("onlem_anahtar") != anahtar:
        st.session_state["onlem_anahtar"] = anahtar
        st.session_state["onlem_secim"] = oneri["onlemler"]
    elif "onlem_secim" not in st.session_state:
        # Streamlit başka adıma geçilince seçim kutusunun durumunu siler; son seçim geri yüklenir
        st.session_state["onlem_secim"] = [o for o in st.session_state.get("onlem_secim_son", oneri["onlemler"])
                                           if o in gecerli]

    ad = {o["onlem_id"]: f"{o['onlem_id']} · {o['ad']}" for o in m.katalog}
    secim = st.multiselect("Uygulanacak önlemler (en iyi bileşim önerildi, değiştirebilirsiniz)",
                           [o["onlem_id"] for o in m.katalog], key="onlem_secim", format_func=ad.get)
    st.session_state["onlem_secim_son"] = list(secim)
    s = m.senaryo(secim, guven)

    if s["efor_saat"] > butce:
        st.warning(f"Seçim bütçeyi aşıyor: {s['efor_saat']:.0f} saat > {butce} saat.")
    elif sorted(secim) != sorted(oneri["onlemler"]) and s["yol_riski"] > oneri["yol_riski"] + 1e-6:
        st.info(f"Bu bütçede en iyi bileşim kalan yol riskini {oneri['yol_riski']:.2f}'e indiriyor "
                f"({', '.join(oneri['onlemler']) or 'önlem yok'}).")

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Kalan yol riski", f"{s['yol_riski']:.2f}", _yuzde(taban["yol_riski"], s["yol_riski"]),
              delta_color="inverse", help=f"Kritik varlıklara giden {len(m.yollar)} yolun toplam riski.")
    k2.metric("Kalan zafiyet riski", f"{s['zafiyet_riski']:.2f}",
              _yuzde(taban["zafiyet_riski"], s["zafiyet_riski"]), delta_color="inverse")
    kes0, kes1 = taban["yol_durum"].get("kesildi", 0), s["yol_durum"].get("kesildi", 0)
    k3.metric("Kesilen yol", f"{kes1} / {len(m.yollar)}", f"+{kes1 - kes0}" if kes1 > kes0 else None,
              help=f"Riski hesaplanabilen {len(m.yollar)} yol üzerinden; {m.risksiz_yol} yolda CVSS vektörü eksik."
              if getattr(m, "risksiz_yol", 0) else None)
    k4.metric("Efor", f"{s['efor_saat']:.0f} / {butce} saat")
    k4.caption("Hizmet kesintisi gerektiren önlem var." if "var" in s["kesinti"] else "Hizmet kesintisi gerekmiyor.")
    st.caption(f"Önlemlerden önce (mevcut kontroller açık): yol riski {taban['yol_riski']:.2f}, "
               f"zafiyet riski {taban['zafiyet_riski']:.2f}, {kes0} yol kesik.")

    _plani_acikla(mod, m, secim, guven, butce)

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

    st.subheader("Grafik")
    st.caption("Kesilen kenarlar gri ve kesikli, zayıflayanlar turuncu; kırmızı yollar kalan en riskli 5 yol. "
               "Düğüm rengi kalan risk. Üç grafik aynı yerleşimde: seçimi değiştirince yalnızca durumlar değişir.")
    secenekler = ["Seçilen önlemlerden sonra", "Bugün (kontroller açık)", "Kontroller öncesi"]
    secili = ortak.grafik_secici(secenekler, "onlem_grafik")
    if secili == secenekler[0]:
        with st.spinner("Grafik çiziliyor..."):
            components.html(ortak.grafik_html(_senaryo_html(tuple(sorted(secim)), guven, anahtar_m)), height=980, scrolling=True)
    elif anahtar_m:
        bugun_ve_once_grafik(secili == secenekler[1], anahtar_m)
    else:
        ortak.grafik_goster(GRAPH_DIR / ("attack_graph_after.html" if secili == secenekler[1] else "attack_graph_v2.html"))

    if anahtar_m:
        return
    with st.expander("Bütçeye göre kalan yol riski (ekibin raporundaki eğri)"):
        png = AI_DIR.parent / "report" / "img" / "onlem-butce.png"
        if png.exists():
            st.image(str(png), width="stretch")
            st.caption("`python ai/onlem_secimi.py` ile üretilir (plan aşaması, gerekçe dayanağı). "
                       "Ayrıntı: `docs/onlem-secimi.md`.")
        else:
            st.caption("Eğri henüz üretilmedi: `python ai/onlem_secimi.py`.")


def bugun_ve_once_grafik(bugun, anahtar_m, yukseklik=980):
    """Çalıştırmanın grafiği: kontroller öncesi (4. adımdaki grafik) ya da bugün (kontroller açık)."""
    if bugun:
        with st.spinner("Grafik çiziliyor..."):
            components.html(ortak.grafik_html(_senaryo_html((), "gerekce", anahtar_m, "Bugün (kontroller açık)")),
                            height=yukseklik, scrolling=True)
    else:
        ortak.grafik_goster(runs.run_dir(anahtar_m[0]) / "graph" / "attack_graph.html")


def _plani_acikla(mod, m, secim, guven, butce):
    """Seçilen planı yerel modelle Türkçe açıklar. Sayılar motordan gelir; model yalnızca anlatır."""
    from pipeline import ai_aciklama, ai_skor
    ok, mesaj, model = ortak.ollama()
    anahtar = ("plan_aciklama", tuple(sorted(secim)), guven, butce)
    is_anahtari = f"plan_aciklama:{'|'.join(sorted(secim))}:{guven}:{butce}"
    suruyor = isler.ilerleme(is_anahtari, iptal=False)
    bitti = isler.sonuc(is_anahtari)
    if bitti:
        st.session_state[anahtar] = bitti.sonuc if bitti.durum != isler.HATA else (None, bitti.hata, None)
    c1, c2 = st.columns([1, 3])
    if c1.button("Planı AI ile açıkla", disabled=not ok or not secim or suruyor, key="plan_acikla",
                 help="Yerel model (Ollama) seçilen önlemleri, kazanımı ve kalan en riskli yolu Türkçe "
                      "anlatır. Model hesap yapmaz: bütün sayılar önlem motorundan verilir."):
        veri = ai_aciklama.baglam(m, secim, guven, butce)
        mm = ai_skor.model_modulu()
        run_dir = runs.run_dir(st.session_state["run_id"]) if st.session_state.get("run_id") else None

        def _is(is_):
            is_.ilerle(None, f"{model} planı yorumluyor…")
            metin, ek = ai_aciklama.acikla(veri, mm.MODEL_NAME, mm.OPTIONS, run_dir=run_dir)
            return metin, ek, veri
        isler.baslat(is_anahtari, "Plan açıklaması", _is)
        st.rerun()
    c2.caption(mesaj if not ok else ("Önlem seçin." if not secim else
               "Model yalnızca anlatır; yazdığı her sayı hesaplanan değerlerle karşılaştırılır."))
    sonuc = st.session_state.get(anahtar)
    if not sonuc:
        return
    metin, ek, veri = sonuc
    with st.container(border=True):
        if metin is None:
            st.warning(ek)
            return
        st.markdown(f"**AI açıklaması** · `{model}`")
        st.markdown(metin)
        if ek:
            st.warning("Metinde hesaplanan verilerde olmayan sayılar var, dikkatle okuyun: "
                       + ", ".join(f"{x:g}" for x in ek))
        else:
            st.caption("Sayı denetimi: metindeki bütün sayılar hesaplanan değerlerde var.")
        with st.expander("Modele verilen veri"):
            st.json(veri)
