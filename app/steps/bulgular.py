"""3. adım: aday bulguların listelenmesi, seçilmesi ve envanterle karşılaştırılması."""

import datetime

import pandas as pd
import streamlit as st

from config import RAW_DIR
from pipeline import envanter, fark, parsers, runs
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

    st.header("3. Bulgular")
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
    if st.button(f"Seçimi kaydet ({len(secili)} kayıt)", type="primary", disabled=not secili):
        satirlar, varsayilanlar = envanter.olustur(secili, adaylar, env_rows, eslesme)
        envanter.kaydet(rdir / "inventory.csv", sutunlar, satirlar)
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
            st.info("Yeni kayıtlarda bazı alanlar varsayılan değerlerle dolduruldu "
                    "(varlık kritikliği 3, yetkinlik yok, ZAP/challenge için giriş noktası 'web'). "
                    "Grafikte bu kayıtlar envanterdekiler kadar güvenilir değildir.")
