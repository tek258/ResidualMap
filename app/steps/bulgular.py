"""3. adım: aday bulguların listelenmesi, seçilmesi ve envanterle karşılaştırılması."""

import datetime

import pandas as pd
import streamlit as st

from config import RAW_DIR
from pipeline import baglanti, envanter, fark, parsers, runs
from steps import isler, ortak, tema
from pipeline.scans import KAYNAK_ADLARI, RAW_FILES

HEDEF_MIN, HEDEF_MAX = 25, 40
KAYNAK_KISA = {"trivy": "Trivy", "zap": "ZAP", "challenges": "Challenge"}


@st.cache_data(show_spinner="Ham veri okunuyor...")
def _adaylar(raw_dir_str, imza):
    # imza: dosyaların değişme zamanları; dosya değişince önbellek yenilenir
    from pathlib import Path
    return parsers.adaylar(Path(raw_dir_str))


def _secim_anahtari(run_id):
    return f"secim_{run_id}"


def _secimi_ayarla(run_id, ids):
    st.session_state[_secim_anahtari(run_id)] = set(ids)
    st.session_state["editor_v"] = st.session_state.get("editor_v", 0) + 1   # tablodaki el düzeltmelerini sıfırla


def _referans_karsilastirma(raw_dir, env_rows):
    """Bu çalıştırmanın ham verisi ile envanterin dayandığı tarama (inventory/raw/)."""
    farklar = fark.referans_farki(raw_dir)
    farkli = {k: v for k, v in farklar.items() if v["durum"] == "farkli"}
    ozet = ", ".join(f"{KAYNAK_KISA[k]}: -{len(v['kaybolan'])} / +{len(v['yeni'])}"
                     for k, v in farkli.items())
    baslik = ("Referans taramayla karşılaştırma: "
              + (ozet if farkli else "fark yok"))
    with st.expander(baslik, expanded=False):
        st.caption("Referans: envanterin dayandığı tarama (`inventory/raw/`). Envanterde "
                   "olmayan bulgular da dahil, hangi bulguların kaybolduğunu ve hangilerinin "
                   "yeni çıktığını gösterir.")
        # Kaybolan bulguların envanterdeki karşılığı, referans verideki eşleşmeden bulunur
        ref_mtime = tuple(p.stat().st_mtime for p in sorted(RAW_DIR.glob("*.json")))
        ref_vid = {a: v for v, a in envanter.eslestir(
            _adaylar(str(RAW_DIR), ref_mtime), env_rows).items() if a}
        for kaynak, v in farklar.items():
            ad = KAYNAK_ADLARI[kaynak]
            if v["durum"] == "ayni":
                st.markdown(f"**{ad}:** referans dosyanın aynısı kullanıldı, fark yok.")
            elif v["durum"] == "toplanmadi":
                st.markdown(f"**{ad}:** bu çalıştırmada toplanmadı.")
            elif v["durum"] == "referans_yok":
                st.markdown(f"**{ad}:** `inventory/raw/` altında referans dosya yok.")
            else:
                birim = "bulgu türü" if kaynak == "zap" else "kayıt"
                tarih = (f" ({v['ref_tarih']} → {v['bu_tarih']})"
                         if v["ref_tarih"] and v["bu_tarih"] else "")
                st.markdown(f"**{ad}:** {v['ref_sayi']} → {v['bu_sayi']} {birim}{tarih}")
                for baslik_, liste in (("Kaybolan", v["kaybolan"]), ("Yeni", v["yeni"])):
                    if not liste:
                        continue
                    st.markdown(f"{baslik_} ({len(liste)})")
                    st.dataframe(pd.DataFrame([{
                        "Ad": x["ad"],
                        "Önem": x["onem"],
                        "Envanter": ref_vid.get(x["aday_id"], "") if baslik_ == "Kaybolan" else "",
                    } for x in liste]), hide_index=True,
                        height=min(38 + 35 * len(liste), 280))
                if kaynak == "zap" and any(ref_vid.get(x["aday_id"]) for x in v["kaybolan"]):
                    st.caption("ZAP'ta envanter kaydı, birleştirilmiş türlerden en az biri "
                               "hâlâ bulunuyorsa 'bulunan' sayılır; kaybolan tür yine burada listelenir.")


def render():
    run_id = st.session_state["run_id"]
    rdir = runs.run_dir(run_id)
    raw_dir = rdir / "raw"
    meta = runs.load_meta(run_id)

    tema.baslik("Adım 3", "Bulgular", "Grafiğe hangi zafiyetler girecek?")
    mevcut = [k for k in RAW_FILES if (raw_dir / RAW_FILES[k]).exists()]
    if not mevcut:
        st.warning("Bu çalıştırmada ham veri yok. Önce 2. adımda en az bir kaynak toplayın.")
        return

    imza = tuple((raw_dir / RAW_FILES[k]).stat().st_mtime for k in mevcut)
    adaylar = _adaylar(str(raw_dir), imza)
    sutunlar, env_rows = envanter.yukle_envanter()
    eslesme = envanter.eslestir(adaylar, env_rows)
    aday_vid = {a: v for v, a in eslesme.items() if a}

    # Seçim durumu: kayıtlı seçim varsa onu, yoksa kural seçimini kullan
    key = _secim_anahtari(run_id)
    if key not in st.session_state:
        kayitli = meta["steps"].get("bulgular", {}).get("secili")
        st.session_state[key] = set(kayitli) if kayitli else {a["aday_id"] for a in adaylar if a["kural"]}
    secili = st.session_state[key]

    st.caption("Kural tabanlı ön seçim: Trivy'de CRITICAL/HIGH, ZAP'ta Medium ve üstü. "
               "Challenge'larda önem bilgisi olmadığı için ön seçim yok. Seçimi tablodan "
               "düzeltebilir ya da ekibin dondurulmuş envanterini uygulayabilirsiniz.")

    # --- Üst özet ---
    cols = st.columns(len(mevcut) + 1)
    for c, k in zip(cols, mevcut):
        n_aday = sum(1 for a in adaylar if a["kaynak"] == k)
        n_sec = sum(1 for a in adaylar if a["kaynak"] == k and a["aday_id"] in secili)
        c.metric(KAYNAK_ADLARI[k], f"{n_sec} / {n_aday}", help="seçili / aday")
    toplam = len(secili)
    durum = "hedef aralıkta" if HEDEF_MIN <= toplam <= HEDEF_MAX else f"hedef {HEDEF_MIN}-{HEDEF_MAX}"
    cols[-1].metric("Seçili toplam", toplam, durum,
                    delta_color="normal" if HEDEF_MIN <= toplam <= HEDEF_MAX else "inverse")

    b1, b2, b3, _ = st.columns([1, 1.4, 1, 2])
    if b1.button("Kurala göre seç"):
        _secimi_ayarla(run_id, [a["aday_id"] for a in adaylar if a["kural"]]); st.rerun()
    if b2.button("Dondurulmuş envanteri uygula", type="primary", disabled=not env_rows):
        _secimi_ayarla(run_id, aday_vid.keys()); st.rerun()
    if b3.button("Seçimi temizle"):
        _secimi_ayarla(run_id, []); st.rerun()

    # --- Filtreler ---
    f1, f2, f3 = st.columns([2, 1.2, 2])
    kaynak_f = f1.multiselect("Kaynak", mevcut, default=mevcut,
                              format_func=lambda k: KAYNAK_KISA[k])
    gorunum = f2.selectbox("Göster", ["Tümü", "Seçililer", "Kurala uyanlar", "Envanterdekiler", "Bayraklılar"])
    ara = f3.text_input("Ara (ad, CVE, CWE)", "")

    def gorunsun(a):
        if a["kaynak"] not in kaynak_f:
            return False
        if gorunum == "Seçililer" and a["aday_id"] not in secili:
            return False
        if gorunum == "Kurala uyanlar" and not a["kural"]:
            return False
        if gorunum == "Envanterdekiler" and a["aday_id"] not in aday_vid:
            return False
        if gorunum == "Bayraklılar" and not a["bayrak"]:
            return False
        q = ara.strip().lower()
        return not q or q in f"{a['ad']} {a['cve_id']} {a['cwe_id']}".lower()

    gorunen = sorted((a for a in adaylar if gorunsun(a)),
                     key=lambda a: (list(RAW_FILES).index(a["kaynak"]), -a["sira"], a["ad"]))
    df = pd.DataFrame([{
        "id": a["aday_id"],
        "Seç": a["aday_id"] in secili,
        "Kaynak": KAYNAK_KISA[a["kaynak"]],
        "Ad": a["ad"],
        "Önem": a["onem"],
        "CWE": a["cwe_id"],
        "CVSS": float("nan") if a["cvss_score"] is None else a["cvss_score"],   # boş görünsün
        "Envanter": aday_vid.get(a["aday_id"], ""),
        "Bayrak": a["bayrak"],
        "Kanıt": a["kanit"],
    } for a in gorunen], columns=["id", "Seç", "Kaynak", "Ad", "Önem", "CWE", "CVSS",
                                   "Envanter", "Bayrak", "Kanıt"])

    st.caption(f"{len(gorunen)} aday gösteriliyor.")
    duzenli = st.data_editor(
        df,
        key=f"editor_{run_id}_{st.session_state.get('editor_v', 0)}_{gorunum}_{'-'.join(kaynak_f)}_{ara}",
        hide_index=True,
        height=420,
        disabled=[c for c in df.columns if c != "Seç"],
        column_config={
            "id": None,   # gizli
            "Seç": st.column_config.CheckboxColumn(width="small"),
            "Ad": st.column_config.TextColumn(width="large"),
            "CVSS": st.column_config.NumberColumn(format="%.1f", width="small"),
            "Envanter": st.column_config.TextColumn(help="Dondurulmuş envanterde karşılık gelen kayıt"),
            "Kanıt": st.column_config.TextColumn(width="large"),
        },
    )
    for _, row in duzenli.iterrows():   # tablodaki işaretlemeleri seçime yansıt
        (secili.add if row["Seç"] else secili.discard)(row["id"])

    # --- Envanterle karşılaştırma ---
    k = envanter.karsilastir(adaylar, env_rows, eslesme)
    with st.expander(f"Envanterle karşılaştırma: {len(k['bulunan'])}/{len(env_rows)} kayıt bu veride bulundu",
                     expanded=bool(k["bulunamayan"])):
        st.markdown(
            f"- **Bulunan:** {len(k['bulunan'])}\n"
            f"- **Bulunamayan** (kaynağı yüklü ama bu veride yok): {len(k['bulunamayan'])}\n"
            f"- **Kaynağı toplanmamış:** {len(k['yuklenmemis'])}\n"
            f"- **Yeni** (kurala uyuyor, envanterde yok): {len(k['yeni'])}"
        )
        if k["bulunamayan"]:
            st.markdown("**Bulunamayan kayıtlar**")
            st.dataframe(pd.DataFrame([{"Kayıt": r["vuln_id"], "Ad": r["name"],
                                        "Kaynak": KAYNAK_KISA[envanter.satir_kaynagi(r)]}
                                       for r in k["bulunamayan"]]), hide_index=True)
        if k["yeni"]:
            st.markdown("**Yeni adaylar**")
            st.dataframe(pd.DataFrame([{"Ad": a["ad"], "Önem": a["onem"],
                                        "CVSS": float("nan") if a["cvss_score"] is None else a["cvss_score"]}
                                       for a in sorted(k["yeni"], key=lambda a: -a["sira"])]),
                         hide_index=True, height=240)

    _referans_karsilastirma(raw_dir, env_rows)

    # --- Kaydet ---
    st.divider()
    ai_suruyor = isler.suruyor_mu(f"ai_baglanti_{st.session_state['run_id']}")
    if st.button(f"Seçimi kaydet ({len(secili)} kayıt)", type="primary", disabled=not secili or ai_suruyor,
                 help="AI bağlantı önerisi sürüyor; bitince kaydedebilirsiniz." if ai_suruyor else None):
        satirlar, varsayilanlar = envanter.olustur(secili, adaylar, env_rows, eslesme)
        # Yeni kayıtların grafiğe bağlantısı: önceki kayıtta AI ya da elle verilmiş kararlar korunur,
        # boş kalanlar kuraldan (ekip kuralı, MITRE CWE etkisi) önerilir.
        _onceki_kararlari_tasi(rdir / "inventory.csv", satirlar, set(varsayilanlar))
        belirsiz = baglanti.onerileri_uygula(satirlar, set(varsayilanlar))
        envanter.kaydet(rdir / "inventory.csv", _sutunlar(sutunlar), satirlar)
        meta["steps"]["bulgular"] = {
            "secili": sorted(secili),
            "kayit": len(satirlar),
            "envanterden": len(satirlar) - len(varsayilanlar),
            "yeni": len(varsayilanlar),
            "varsayilanlar": varsayilanlar,
            "zaman": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        runs.save_meta(run_id, meta)
        st.success(f"`runs/{run_id}/inventory.csv` yazıldı: {len(satirlar)} kayıt "
                   f"({len(satirlar) - len(varsayilanlar)} envanterden, {len(varsayilanlar)} yeni). "
                   "Sol menüden 4. adıma geçin.")
        if varsayilanlar:
            st.info(f"{len(varsayilanlar)} yeni kayıt için grafikteki hedef kuraldan önerildi"
                    + (f"; {len(belirsiz)} kaydın hedefi belirsiz" if belirsiz else "")
                    + ". Aşağıdaki \"Grafiğe bağlantı\" tablosundan kontrol edin.")

    _baglanti_bolumu(run_id, rdir, meta, env_rows)


def _sutunlar(sutunlar):
    return list(sutunlar) + [c for c in baglanti.EK_SUTUNLAR if c not in sutunlar]


def _onceki_kararlari_tasi(yol, satirlar, yeni_idler):
    """Seçim yeniden kaydedilince, aynı kayıt için daha önce AI ya da elle verilmiş bağlantı
    kararlarını yeni satırlara taşır."""
    import csv
    if not yol.exists():
        return
    with open(yol, encoding="utf-8", newline="") as f:
        onceki = {(r["vuln_id"], r.get("name")): r for r in csv.DictReader(f)}
    alanlar = baglanti.EK_SUTUNLAR + ["entry_point", "requires_capability", "grants_capability"]
    for r in satirlar:
        o = onceki.get((r["vuln_id"], r.get("name")))
        if r["vuln_id"] in yeni_idler and o and o.get("hedef_kaynagi") in (baglanti.KAYNAK_AI, baglanti.KAYNAK_ELLE):
            r.update({k: o.get(k, "") for k in alanlar})


def _ai_baglanti_is(is_, yol, hedef_ai, envd):
    """Arka planda: her kayıt için model önerisi. Her öneriden sonra envanter dosyası yeniden okunup
    yalnızca o satır güncellenir; iş yarıda kalırsa alınan öneriler kaybolmaz."""
    alinan, hatalar = 0, []
    for i, r in enumerate(hedef_ai, start=1):
        if is_.iptal_mi():
            break
        is_.ilerle((i - 1) / len(hedef_ai), f"{r['vuln_id']} modele soruluyor ({i}/{len(hedef_ai)})")
        oneri, hata = baglanti.ai_onerisi(r, envd)
        if not oneri:
            hatalar.append(f"{r['vuln_id']}: {hata}")
            if hata.startswith("Ollama'ya"):
                break
            continue
        sutunlar, satirlar = envanter.yukle_envanter(yol)
        for s in satirlar:
            if s["vuln_id"] == r["vuln_id"] and s.get("hedef_kaynagi") != baglanti.KAYNAK_ELLE:
                baglanti.ai_uygula(s, oneri)
                alinan += 1
        envanter.kaydet(yol, _sutunlar(sutunlar), satirlar)
    return alinan, hatalar


_BELIRSIZ = "— belirsiz —"


def _baglanti_bolumu(run_id, rdir, meta, env_rows):
    """Yeni kayıtların grafikte nereye bağlanacağı: öneri, AI önerisi ve kullanıcı onayı."""
    yol = rdir / "inventory.csv"
    yeni_idler = set(meta["steps"].get("bulgular", {}).get("varsayilanlar", {}))
    if not yol.exists() or not yeni_idler:
        return
    sutunlar, satirlar = envanter.yukle_envanter(yol)
    yeniler = [r for r in satirlar if r["vuln_id"] in yeni_idler]
    if not yeniler:
        return
    for r in yeniler:
        for c in baglanti.EK_SUTUNLAR:
            r.setdefault(c, "")

    st.divider()
    st.subheader("Grafiğe bağlantı")
    st.caption("Dondurulmuş envanterde olmayan kayıtların grafikte nereye bağlanacağı. Hedef sırayla "
               "ekibin CWE kuralından, MITRE CWE kataloğundaki teknik etkiden ya da AI önerisinden gelir; "
               "son karar sizin. Değiştirdiğiniz satırlar \"elle\" olarak işaretlenir. Hedefi belirsiz "
               "kayıtlar grafikte hiçbir yola girmez.")
    sayim = {k: sum(1 for r in yeniler if (r.get("hedef_kaynagi") or "") == k)
             for k in (baglanti.KAYNAK_EKIP, baglanti.KAYNAK_CWE, baglanti.KAYNAK_AI, baglanti.KAYNAK_ELLE)}
    belirsiz = [r for r in yeniler if not r.get("hedef")]
    c = st.columns(5)
    c[0].metric("Ekip kuralı", sayim[baglanti.KAYNAK_EKIP])
    c[1].metric("MITRE CWE etkisi", sayim[baglanti.KAYNAK_CWE])
    c[2].metric("AI önerisi", sayim[baglanti.KAYNAK_AI])
    c[3].metric("Elle", sayim[baglanti.KAYNAK_ELLE])
    c[4].metric("Hedefi belirsiz", len(belirsiz))

    # --- AI önerisi ---
    ok, mesaj, model = ortak.ollama()
    anahtar = f"ai_baglanti_{run_id}"
    suruyor = isler.ilerleme(anahtar)
    bitti = isler.sonuc(anahtar)
    if bitti:
        if bitti.durum == isler.HATA:
            st.error(f"AI önerisi yarıda kaldı: {bitti.hata}")
        else:
            alinan, hatalar = bitti.sonuc
            (st.warning if hatalar else st.success)(
                ("İptal edildi. " if bitti.durum == isler.IPTAL else "")
                + f"{alinan} kayıt için AI önerisi alındı ({bitti.sure():.0f} sn)."
                + (" Öneri alınamayanlar: " + "; ".join(hatalar[:5]) if hatalar else ""))
    a1, a2, a3 = st.columns([1.4, 1.2, 2.4])
    hedef_ai = None
    if a1.button(f"AI ile öner: belirsizler ({len(belirsiz)})", type="primary",
                 disabled=not ok or not belirsiz or suruyor, key="ai_belirsiz"):
        hedef_ai = belirsiz
    if a2.button(f"AI ile öner: hepsi ({len(yeniler)})", disabled=not ok or suruyor, key="ai_hepsi",
                 help="Kuraldan gelen öneriler dahil bütün yeni kayıtlar modele sorulur; elle "
                      "değiştirilenlere dokunulmaz."):
        hedef_ai = [r for r in yeniler if r.get("hedef_kaynagi") != baglanti.KAYNAK_ELLE]
    a3.caption(mesaj + (" Kayıt başına ~3-5 sn." if ok else ""))
    if hedef_ai:
        envd = {**{r["vuln_id"]: r for r in env_rows}, **{r["vuln_id"]: r for r in satirlar}}
        isler.baslat(anahtar, f"AI bağlantı önerisi ({run_id})",
                     lambda is_: _ai_baglanti_is(is_, yol, [dict(r) for r in hedef_ai], envd))
        st.rerun()

    # --- Onay tablosu ---
    etiket = {k: v for k, v in baglanti.HEDEFLER.items()}
    ters = {v: k for k, v in etiket.items()}
    df = pd.DataFrame([{
        "Kayıt": r["vuln_id"], "Ad": r["name"], "CWE": r.get("cwe_id", ""),
        "Hedef": etiket.get(r.get("hedef"), _BELIRSIZ),
        "Giriş": r.get("entry_point") or "web",
        "Ön koşul": r.get("requires_capability") or "none",
        "Kazanım": r.get("grants_capability") or "none",
        "Kaynak": r.get("hedef_kaynagi") or "-",
        "Gerekçe": r.get("hedef_gerekcesi", ""),
    } for r in sorted(yeniler, key=lambda r: (bool(r.get("hedef")), r["vuln_id"]))])
    duz = st.data_editor(
        df, key=f"baglanti_{run_id}_{meta['steps'].get('bulgular', {}).get('zaman', '')}",
        hide_index=True, height=min(80 + 35 * len(df), 460),
        disabled=["Kayıt", "Ad", "CWE", "Kaynak", "Gerekçe"],
        column_config={
            "Hedef": st.column_config.SelectboxColumn(options=[_BELIRSIZ, *etiket.values()], required=True),
            "Giriş": st.column_config.SelectboxColumn(options=baglanti.GIRISLER, required=True),
            "Ön koşul": st.column_config.SelectboxColumn(options=baglanti.YETKINLIKLER, required=True,
                                                         help="Bu kaydı sömürmek için önce elde edilmesi gereken yetkinlik "
                                                              "(docs/yetkinlik-sozlugu.md). none değilse kayıt girişe değil, "
                                                              "bu yetkinliği kazandıran kayda bağlanır."),
            "Kazanım": st.column_config.SelectboxColumn(options=baglanti.YETKINLIKLER, required=True),
            "Ad": st.column_config.TextColumn(width="medium"),
            "Gerekçe": st.column_config.TextColumn(width="large"),
        },
    )
    if st.button("Bağlantıları kaydet", key="baglanti_kaydet", disabled=suruyor,
                 help="AI önerisi sürüyor; bitince kaydedebilirsiniz." if suruyor else None):
        by = {r["vuln_id"]: r for r in yeniler}
        degisen = 0
        for _, s in duz.iterrows():
            r = by[s["Kayıt"]]
            yeni = {"hedef": ters.get(s["Hedef"], ""), "entry_point": s["Giriş"],
                    "requires_capability": s["Ön koşul"], "grants_capability": s["Kazanım"]}
            if any((r.get(k) or ("none" if "capability" in k else "")) != v for k, v in yeni.items()):
                once = etiket.get(r.get("hedef"), "belirsiz")
                r.update(yeni)
                r["hedef_kaynagi"] = baglanti.KAYNAK_ELLE
                r["hedef_gerekcesi"] = f"Kullanıcı değiştirdi (önceki öneri: {once})."
                degisen += 1
        envanter.kaydet(yol, _sutunlar(sutunlar), satirlar)
        meta["steps"].pop("grafik", None)          # grafik eski bağlantılarla üretildi
        runs.save_meta(run_id, meta)
        st.success(f"Kaydedildi ({degisen} satır değişti). Grafiği 4. adımda yeniden oluşturun.")
