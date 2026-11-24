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
from steps import isler, ortak, tema


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
        import csv
        from collections import Counter
        with open(inv, encoding="utf-8", newline="") as f:
            yeni = [r for r in csv.DictReader(f) if r["vuln_id"] in b.get("varsayilanlar", {})]
        kaynak = Counter(r.get("hedef_kaynagi") or "belirsiz" for r in yeni if r.get("hedef")) 
        belirsiz = [r["vuln_id"] for r in yeni if not r.get("hedef")]
        dagilim = ", ".join(f"{v} {k}" for k, v in kaynak.most_common())
        st.info(f"{b['yeni']} yeni kayıt grafiğe 3. adımdaki bağlantı kararlarıyla girer"
                + (f" ({dagilim})" if dagilim else "") + ". Varlık kritikliği gibi bazı alanlar "
                "varsayılan değerlerdedir; bu kayıtların yeri envanterdekiler kadar güvenilir değildir.")
        if belirsiz:
            st.warning(f"{len(belirsiz)} yeni kaydın hedefi belirsiz; bu kayıtlar hiçbir saldırı yoluna "
                       f"girmez: {', '.join(belirsiz[:12])}{' …' if len(belirsiz) > 12 else ''}. "
                       "3. adımdaki \"Grafiğe bağlantı\" tablosundan hedef seçin ya da AI önerisi alın.")

    html = out / graf.CIKTILAR["html"]
    if html.exists() and inv.stat().st_mtime > html.stat().st_mtime:
        st.warning("Envanter grafik üretildikten sonra değişti. Grafiği yeniden oluşturun.")

    ai_suruyor = isler.suruyor_mu(f"ai_skor_{run_id}")
    if st.button("Grafiği oluştur", type="primary", disabled=ai_suruyor,
                 help="AI skorlaması bitince grafik kendiliğinden yeniden oluşturulur." if ai_suruyor else None):
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
    anahtar = f"ai_skor_{run_id}"
    suruyor = isler.ilerleme(anahtar)
    bitti = isler.sonuc(anahtar)
    if bitti:
        if bitti.durum == isler.HATA:
            st.error(f"Skorlama yarıda kaldı: {bitti.hata}")
        else:
            s = bitti.sonuc
            if s["basarisiz"]:
                st.warning(f"Skorlanamayan kayıtlar (geçersiz yanıt): {', '.join(s['basarisiz'])}")
            st.success(("İptal edildi; o ana kadar " if bitti.durum == isler.IPTAL else "")
                       + f"{s['skorlanan']} kayıt {s['sure_sn']} sn'de skorlandı; grafik güncellendi.")
    hepsi = st.checkbox("Hazır skorları da yeniden hesapla (tüm kayıtlar)", value=False,
                        disabled=not ok or suruyor)
    n = len(satirlar) if hepsi else eksik
    if st.button(f"{n} kaydı modelle skorla (~{max(1, round(n * 3 / 60))} dk)",
                 disabled=not ok or n == 0 or suruyor):
        isler.baslat(anahtar, f"AI skorlama ({run_id})", lambda is_: _skorla_is(is_, run_id, rdir, inv, out, hepsi))
        st.rerun()

    st.caption("CVSS ve AI sıralaması yan yana. Eşit skorlar aynı sırayı alır. AI sınıfı skordan "
               "türetilir (≥9 Kritik, ≥7 Yüksek, ≥4 Orta, altı Düşük).")
    st.dataframe(pd.DataFrame(satirlar), hide_index=True, use_container_width=True,
                 column_config={"AI gerekçesi": st.column_config.TextColumn(width="large")})

    _model_ne_dusundu(run_id, rdir, inv, out, satirlar, ok)


def _skorla_is(is_, run_id, rdir, inv, out, hepsi):
    """Arka planda: skorla, grafiği yeniden üret, özeti çalıştırmaya yaz."""
    sonuc = ai_skor.skorla(rdir, hepsi=hepsi, iptal=is_.iptal_mi, on_progress=lambda i, t, vid: is_.ilerle(
        0.95 * i / t if t else 0.95, f"{i}/{t} kayıt" + (f" · {vid}" if vid else "")))
    is_.ilerle(0.96, "Grafik yeni skorlarla yeniden oluşturuluyor…")
    graf.uret(inv, out)
    meta = runs.load_meta(run_id)        # o arada başka adımda kaydedilmiş olabilir: en güncelini al
    meta["steps"].setdefault("grafik", {})["ai"] = sonuc | {
        "zaman": datetime.datetime.now().isoformat(timespec="seconds")}
    runs.save_meta(run_id, meta)
    return sonuc


_HEDEF_TR = {"node_target_admin": "Yönetici erişimi", "node_target_rce": "Kod çalıştırma",
             "node_target_account_takeover": "Hesap ele geçirme", "node_target_leak": "Veri sızıntısı",
             "node_target_dos": "Hizmet kesintisi"}


def _model_ne_dusundu(run_id, rdir, inv, out, satirlar, ollama_ok):
    """Seçilen kayıt için modelin gördüğü kanıt, verdiği karar ve gerekçesi; CVSS ile farkı ve
    kaydın grafikteki yeri. İsteğe bağlı: kaydı canlı skorlama."""
    import csv
    import json
    st.divider()
    st.subheader("Model ne düşündü?")
    st.caption("Risk skoru yerel bir dil modelinden gelir (Ollama, temperature 0, sabit seed). Model CVSS'i "
               "kopyalamaz: kanıtın türüne (uygulamada doğrulanmış / bağımlılık sürümü / pasif tarama), "
               "kimlik doğrulama ihtiyacına ve etkisine bakarak rubrikten bir bant seçer. Uzman etiketleriyle "
               "sınıf uyumu 24/33, yalnızca CVSS ile 19/33 (docs/model-v2-degerlendirme.md).")
    skorlu = [s for s in satirlar if s["AI skoru"] is not None]
    if not skorlu:
        st.info("Bu çalıştırmada AI skoru olan kayıt yok.")
        return
    # Varsayılan: modelin CVSS'ten en çok ayrıldığı kayıt (en öğretici örnek)
    fark = lambda s: abs((s["AI skoru"] or 0) - (s["CVSS"] or 0)) if s["CVSS"] is not None else -1
    en_farkli = max(skorlu, key=fark)["Kayıt"]
    # Seçenek sırası sabit (kayıt numarası): skor değişince liste sıfırlanmasın
    secenek = sorted(s["Kayıt"] for s in satirlar)
    etiket = {s["Kayıt"]: f"{s['Kayıt']} · {s['Ad'][:60]}"
              + (f"  (AI {s['AI skoru']:.1f} / CVSS {s['CVSS']:.1f})" if s["AI skoru"] is not None and s["CVSS"] is not None else "")
              for s in satirlar}
    if st.session_state.get(f"model_kayit_{run_id}") not in secenek:
        st.session_state[f"model_kayit_{run_id}"] = en_farkli
    vid = st.selectbox("Kayıt (açılışta modelin CVSS'ten en çok ayrıldığı kayıt seçili)", secenek,
                       format_func=etiket.get, key=f"model_kayit_{run_id}")
    s = next(x for x in satirlar if x["Kayıt"] == vid)
    with open(inv, encoding="utf-8", newline="") as f:
        r = next(x for x in csv.DictReader(f) if x["vuln_id"] == vid)
    kanit, prompt, model = ai_skor.modele_giden(rdir, vid)

    k1, k2, k3 = st.columns([1.25, 1, 1])
    with k1:
        st.markdown("**1. Modele giden kanıt**")
        st.code(kanit, language=None, wrap_lines=True)
    with k2:
        st.markdown(f"**2. Modelin kararı** · `{model}`")
        if s["AI skoru"] is None:
            st.info("Bu kayıt henüz skorlanmadı.")
        else:
            m1, m2 = st.columns(2)
            m1.metric("AI skoru", f"{s['AI skoru']:.1f}", s["AI sınıfı"], delta_color="off")
            if s["CVSS"] is not None:
                fark_ = s["AI skoru"] - s["CVSS"]
                m2.metric("CVSS", f"{s['CVSS']:.1f}", f"AI {fark_:+.1f}", delta_color="off")
            st.markdown(f"> {s['AI gerekçesi'] or '(gerekçe yok)'}")
            st.caption("Gerekçe modelin kendi cümlesi (İngilizce prompt, İngilizce yanıt).")
            st.caption(f"Sıra: AI {s['AI sırası']} · CVSS {s['CVSS sırası']} · kaynak: {s['Kaynak']}")
        if ollama_ok and st.button("Bu kaydı şimdi canlı skorla", key=f"canli_{run_id}_{vid}",
                                   help="Model bu kayıt için şimdi yeniden çalışır (~3-5 sn); sonuç bu "
                                        "çalıştırmanın skor dosyasına yazılır."):
            with st.spinner(f"{model} çalışıyor..."):
                skor, sinif, gerekce, sure = ai_skor.skorla_tek(rdir, vid)
            st.session_state[f"canli_sonuc_{run_id}"] = (
                vid, None if skor is None else f"{sure} sn'de yeniden skorlandı: {skor:.1f} ({sinif}). {gerekce}")
            st.rerun()       # tablo ve kart yeni skorla yeniden çizilsin
        son = st.session_state.get(f"canli_sonuc_{run_id}")
        if son and son[0] == vid:
            (st.success if son[1] else st.warning)(son[1] or "Model geçerli bir yanıt vermedi, tekrar deneyin.")
    with k3:
        st.markdown("**3. Grafikteki yeri**")
        edges = json.loads((out / "edges.json").read_text(encoding="utf-8")) if (out / "edges.json").exists() else []
        paths = json.loads((out / "paths.json").read_text(encoding="utf-8")) if (out / "paths.json").exists() else []
        hedefler = sorted({e["target"] for e in edges if e["source"] == vid and e["relation"] == "Leads To"})
        girisler = sorted({e["source"].replace("node_entry_", "") for e in edges
                           if e["target"] == vid and e["relation"] == "Entry Point"})
        zincir = sorted({e["source"] for e in edges if e["target"] == vid and e["relation"] == "Chains To"})
        yollar = [p for p in paths if vid in p["path"]]
        st.markdown(
            f"- **Hedef:** {', '.join(_HEDEF_TR.get(h, h) for h in hedefler) or '— (bağlı değil)'}\n"
            f"- **Giriş:** {', '.join(girisler) or ('zincirle: ' + ', '.join(zincir) if zincir else '—')}\n"
            f"- **Ön koşul / kazanım:** {r.get('requires_capability') or 'none'} / {r.get('grants_capability') or 'none'}\n"
            f"- **Yer aldığı yol:** {len(yollar)}"
            + (f" (en yüksek yol riski {max((p.get('path_risk') or 0) for p in yollar):.2f})" if yollar else ""))
        if r.get("hedef_kaynagi"):
            st.caption(f"Bağlantı kaynağı: {r['hedef_kaynagi']}. {r.get('hedef_gerekcesi', '')}")
        else:
            st.caption("Bağlantı: ekibin dondurulmuş envanteri.")
    with st.expander("Modele gönderilen tam prompt (rubrik, örnekler ve bu kayıt)"):
        st.code(prompt, language=None, wrap_lines=True)

