"""4. adım: seçilen bulgulardan saldırı grafiğinin üretilmesi."""

import datetime
import io
import shutil
import zipfile
from collections import Counter

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from config import FROZEN_INVENTORY
from pipeline import ai_skor, graf, runs
from steps import tema
from steps import ortak


def _ad(ozet, vid):
    return f"{vid} · {ozet['adlar'].get(vid, '')}"


def render():
    run_id = st.session_state["run_id"]
    rdir = runs.run_dir(run_id)
    inv = rdir / "inventory.csv"
    out = rdir / "graph"
    meta = runs.load_meta(run_id)

    tema.baslik("Adım 4", "Saldırı grafiği", "Kritik varlıklara hangi yollarla ulaşılır?")

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
    if ozet["girissiz"]:
        st.warning("Giriş noktası boş ya da geçersiz olan kayıtlar (giriş kenarı eklenmedi; "
                   "geçerli değerler: login, search, api, web, dependency): "
                   + ", ".join(_ad(ozet, v) for v in ozet["girissiz"]))
    if ozet["risksiz_yollar"]:
        st.warning(f"{len(ozet['risksiz_yollar'])} yolun riski hesaplanamadı (yoldaki bir kaydın "
                   "CVSS vektörü eksik). Bu yollar sıralamanın sonunda.")
    if ozet["ulasilamayan"]:
        st.warning("Hiçbir saldırı yolunda yer almayan kayıtlar: "
                   + ", ".join(_ad(ozet, v) for v in ozet["ulasilamayan"]))
    if ozet["sadece_zincirle"]:
        st.caption("Doğrudan giriş noktası olmayan, yalnızca zincirle ulaşılan kayıtlar: "
                   + ", ".join(_ad(ozet, v) for v in ozet["sadece_zincirle"]))

    # --- Grafik ---
    st.markdown("**Saldırı grafiği**")
    st.caption("Yeşil elmas: giriş noktası · Mavi yıldız: hedef · Daireler: zafiyetler (renk AI v2 "
               "skoruna göre, yoksa CVSS) · Kırmızı kenarlar: en riskli 5 yol. Düğüm ve kenarların "
               "üzerine gelince ayrıntılar görünür. Grafik yakınlaştırılıp sürüklenebilir.")
    components.html(ortak.grafik_html(html.read_text(encoding="utf-8")), height=980, scrolling=True)

    _ai_bolumu(run_id, rdir, inv, out, meta)

    # --- İndir ---
    d = st.columns(4)
    for col, (k, etiket, mime) in zip(d, [("edges", "edges.json", "application/json"),
                                          ("paths", "paths.json", "application/json"),
                                          ("html", "Grafik (HTML)", "text/html")]):
        p = out / graf.CIKTILAR[k]
        col.download_button(f"İndir: {etiket}", p.read_bytes(), file_name=p.name, mime=mime)
    d[3].download_button("Hepsini indir (zip)", _zip(run_id, rdir, out),
                         file_name=f"residualmap-{run_id}.zip", mime="application/zip", type="primary")

    gunluk = meta["steps"].get("grafik", {}).get("gunluk")
    if gunluk:
        with st.expander("Script çıktısı"):
            st.code(gunluk, language=None)


def _zip(run_id, rdir, out):
    """Envanter, AI skorları, kenarlar, yollar ve grafik tek dosyada."""
    tampon = io.BytesIO()
    with zipfile.ZipFile(tampon, "w", zipfile.ZIP_DEFLATED) as z:
        for p in [rdir / "inventory.csv", rdir / ai_skor.DOSYA, rdir / "meta.json",
                  *(out / ad for ad in graf.CIKTILAR.values())]:
            if p.exists():
                z.write(p, arcname=p.relative_to(rdir).as_posix())
    return tampon.getvalue()


def _ai_bolumu(run_id, rdir, inv, out, meta):
    st.markdown("**AI önceliklendirme (model v2)**")
    satirlar = ai_skor.tablo(rdir)
    kaynak = Counter(s["Kaynak"] for s in satirlar)
    eksik = kaynak.get("yok", 0)
    c = st.columns(3)
    c[0].metric("Hazır sonuçtan", kaynak.get(ai_skor.HAZIR, 0),
                help="Dondurulmuş envanterde de bulunan kayıtlar: skor ai/results_v2_llm.csv'den.")
    c[1].metric("Bu çalıştırmada modelle", kaynak.get(ai_skor.MODEL, 0))
    c[2].metric("AI skoru yok", eksik, help="Yeni kayıtlar. Grafikte renkleri CVSS'ten gelir.")

    ok, mesaj, model = ortak.ollama()
    (st.caption if ok else st.info)(mesaj)
    hepsi = st.checkbox("Hazır skorları da yeniden hesapla (tüm kayıtlar)", value=False, disabled=not ok)
    n = len(satirlar) if hepsi else eksik
    if st.button(f"{n} kaydı modelle skorla (~{max(1, round(n * 3 / 60))} dk)",
                 disabled=not ok or n == 0):
        bar = st.progress(0.0, text="Başlıyor...")
        sonuc = ai_skor.skorla(rdir, hepsi=hepsi, on_progress=lambda i, t, vid: bar.progress(
            i / t if t else 1.0, text=f"{i}/{t} · {vid}"))
        bar.empty()
        with st.spinner("Grafik yeni skorlarla yeniden oluşturuluyor..."):
            graf.uret(inv, out)
        meta["steps"].setdefault("grafik", {})["ai"] = sonuc | {
            "zaman": datetime.datetime.now().isoformat(timespec="seconds")}
        runs.save_meta(run_id, meta)
        if sonuc["basarisiz"]:
            st.warning(f"Skorlanamayan kayıtlar (geçersiz yanıt): {', '.join(sonuc['basarisiz'])}")
        st.success(f"{sonuc['skorlanan']} kayıt {sonuc['sure_sn']} sn'de skorlandı; grafik güncellendi.")
        st.rerun()

    st.caption("CVSS ve AI sıralaması yan yana. Eşit skorlar aynı sırayı alır. AI sınıfı skordan "
               "türetilir (≥9 Kritik, ≥7 Yüksek, ≥4 Orta, altı Düşük).")
    st.dataframe(pd.DataFrame(satirlar), hide_index=True, use_container_width=True,
                 column_config={"AI gerekçesi": st.column_config.TextColumn(width="large")})

