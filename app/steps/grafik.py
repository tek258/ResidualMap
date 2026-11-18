"""4. adım: seçilen bulgulardan saldırı grafiğinin üretilmesi."""

import datetime
import shutil

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from config import FROZEN_INVENTORY
from pipeline import graf, runs


def _ad(ozet, vid):
    return f"{vid} · {ozet['adlar'].get(vid, '')}"


def render():
    run_id = st.session_state["run_id"]
    rdir = runs.run_dir(run_id)
    inv = rdir / "inventory.csv"
    out = rdir / "graph"
    meta = runs.load_meta(run_id)

    st.header("4. Grafik")

    if not inv.exists():
        st.warning("Bu çalıştırmada henüz envanter yok. 3. adımda bulguları seçip kaydedin "
                   "ya da doğrudan ekibin dondurulmuş envanterini kullanın.")
        if st.button("Dondurulmuş envanteri kullan", disabled=not FROZEN_INVENTORY.exists()):
            shutil.copyfile(FROZEN_INVENTORY, inv)
            meta["steps"]["bulgular"] = {"kaynak": "dondurulmuş envanter", "yeni": 0,
                                         "zaman": datetime.datetime.now().isoformat(timespec="seconds")}
            runs.save_meta(run_id, meta)
            st.rerun()
        return

    b = meta["steps"].get("bulgular", {})
    bilgi = f"Envanter: `runs/{run_id}/inventory.csv`"
    if "kayit" in b:
        bilgi += f" · {b['kayit']} kayıt ({b['envanterden']} envanterden, {b['yeni']} yeni)"
    elif b.get("kaynak"):
        bilgi += f" · {b['kaynak']}"
    st.caption(bilgi)
    if b.get("yeni"):
        st.info(f"{b['yeni']} yeni kayıtta bazı alanlar varsayılan değerlerle dolduruldu "
                "(varlık kritikliği, yetkinlik, giriş noktası). Bu kayıtların grafikteki "
                "yeri envanterdekiler kadar güvenilir değildir.")

    html = out / graf.CIKTILAR["html"]
    if html.exists() and inv.stat().st_mtime > html.stat().st_mtime:
        st.warning("Envanter grafik üretildikten sonra değişti. Grafiği yeniden oluşturun.")

    if st.button("Grafiği oluştur", type="primary"):
        with st.spinner("Kenarlar, yollar ve grafik üretiliyor..."):
            ok, gunluk = graf.uret(inv, out)
        if not ok:
            st.error("Grafik üretilemedi.")
            st.code(gunluk or "(çıktı yok)", language=None)
            return
        ozet = graf.ozetle(inv, out)
        meta["steps"]["grafik"] = {k: v for k, v in ozet.items() if k != "adlar"} | {
            "zaman": datetime.datetime.now().isoformat(timespec="seconds"), "gunluk": gunluk}
        runs.save_meta(run_id, meta)

    if not html.exists():
        return

    ozet = graf.ozetle(inv, out)

    # --- Özet ---
    c = st.columns(5)
    c[0].metric("Zafiyet", ozet["zafiyet"])
    c[1].metric("Kenar", ozet["kenar"])
    c[2].metric("Saldırı yolu", ozet["yol"])
    c[3].metric("Zincir", len(ozet["zincirler"]))
    c[4].metric("Hedefe bağlanamayan", len(ozet["hedefsiz"]))

    sol, sag = st.columns([1, 1.4])
    with sol:
        st.markdown("**Hedef başına yol sayısı**")
        st.dataframe(pd.DataFrame([{"Hedef": h, "Yol": n} for h, n in ozet["hedef_yol"].items()]),
                     hide_index=True)
    with sag:
        st.markdown("**Zincirler**")
        if ozet["zincirler"]:
            for z in ozet["zincirler"]:
                st.markdown(f"- {_ad(ozet, z['kaynak'])} → {_ad(ozet, z['hedef'])}  \n"
                            f"  <small>{z['aciklama']}</small>", unsafe_allow_html=True)
            for y in ozet["zincirli_yollar"]:
                st.caption(f"Yol: {y}")
        else:
            st.caption("Zincir yok. Yetkinlik sütunlarında eşleşen bir kazanım/ön koşul çifti bulunmadı.")

    if ozet["hedefsiz"]:
        st.warning("Hiçbir hedefe bağlanamayan kayıtlar (CWE'leri hedef kümelerinde yok): "
                   + ", ".join(_ad(ozet, v) for v in ozet["hedefsiz"]))
    if ozet["ulasilamayan"]:
        st.warning("Hiçbir saldırı yolunda yer almayan kayıtlar: "
                   + ", ".join(_ad(ozet, v) for v in ozet["ulasilamayan"]))
    if ozet["sadece_zincirle"]:
        st.caption("Doğrudan giriş noktası olmayan, yalnızca zincirle ulaşılan kayıtlar: "
                   + ", ".join(_ad(ozet, v) for v in ozet["sadece_zincirle"]))

    # --- Grafik ---
    st.markdown("**Saldırı grafiği**")
    st.caption("Turuncu: giriş noktası · Mavi: zafiyet · Kırmızı: hedef. Kenarların üzerine "
               "gelince ilişki türü görünür. Grafik yakınlaştırılıp sürüklenebilir.")
    components.html(html.read_text(encoding="utf-8"), height=980, scrolling=True)

    # --- İndir ---
    d = st.columns(3)
    for col, (k, etiket, mime) in zip(d, [("edges", "edges.json", "application/json"),
                                          ("paths", "paths.json", "application/json"),
                                          ("html", "Grafik (HTML)", "text/html")]):
        p = out / graf.CIKTILAR[k]
        col.download_button(f"İndir: {etiket}", p.read_bytes(), file_name=p.name, mime=mime)

    gunluk = meta["steps"].get("grafik", {}).get("gunluk")
    if gunluk:
        with st.expander("Script çıktısı"):
            st.code(gunluk, language=None)
