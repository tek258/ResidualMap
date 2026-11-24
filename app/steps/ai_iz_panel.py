"""AI izi: yan menüde çağrı sayacı ve bu çalıştırmadaki bütün model çağrılarını gösteren pencere."""

import csv
import json
from collections import Counter

import pandas as pd
import streamlit as st

from config import AI_DIR
from pipeline import ai_iz, runs


def _run_dir():
    rid = st.session_state.get("run_id")
    return runs.run_dir(rid) if rid else None


@st.cache_data(show_spinner=False)
def _hazir_sayisi(degisme):
    """Ekibin aynı modelle toplu ürettiği skorlar (ai/results_v2_llm.csv)."""
    yol = AI_DIR / "results_v2_llm.csv"
    with open(yol, encoding="utf-8") as f:
        return sum(1 for r in csv.DictReader(f) if r.get("risk_score_llm"))


def hazir_sayisi():
    yol = AI_DIR / "results_v2_llm.csv"
    return _hazir_sayisi(yol.stat().st_mtime) if yol.exists() else 0


def yan_menu():
    n = ai_iz.sayi(_run_dir())
    if st.button(f"AI izi · {n} model çağrısı", icon=":material/psychology:", use_container_width=True,
                 key="ai_iz_ac", help="Bu çalıştırmada yerel modele yapılan bütün çağrılar: ne soruldu, "
                                      "ne cevap verdi, ne kadar sürdü."):
        pencere()


def _ozet_yanit(s):
    y = s.get("yanit")
    if not s.get("ok") or y is None:
        return f"✗ {s.get('hata', '')}"
    if s["islem"] in (ai_iz.SKOR, ai_iz.SKOR_TEK):
        return f"{y['risk_score']:.1f} ({s.get('sinif', '')}) · {y.get('reason', '')}"
    if s["islem"] == ai_iz.BAGLANTI:
        return f"{y['target'].replace('node_target_', '')} · {y['entry_point']} · {y['reason']}"
    if s["islem"] == ai_iz.PLAN:
        return y["aciklama"][:160] + ("…" if len(y["aciklama"]) > 160 else "")
    return json.dumps(y, ensure_ascii=False)[:160]


@st.dialog("AI izi", width="large")
def pencere():
    rdir = _run_dir()
    satirlar = ai_iz.oku(rdir)
    model = satirlar[-1]["model"] if satirlar else "qwen2.5:7b"
    st.caption(
        ("Bu çalıştırmada" if rdir else "Çalıştırma dışında (6. adım)")
        + f" uygulamanın yerel modele (`{model}`, Ollama, temperature 0, sabit seed) yaptığı bütün çağrılar. "
        "Model bu makinede çalışır; hiçbir veri dışarı gönderilmez. Kayıt: "
        + (f"`runs/{rdir.name}/{ai_iz.DOSYA}`" if rdir else f"`runs/_genel/{ai_iz.DOSYA}`") + ".")
    st.caption(f"Bunlara ek olarak ekip, dondurulmuş envanterin {hazir_sayisi()} kaydını aynı modelle toplu "
               "skorladı (`ai/results_v2_llm.csv`, `ai/model_v2_local_llm.py`); uygulama bu skorları hazır sonuç "
               "olarak kullanır.")
    if not satirlar:
        st.info("Henüz model çağrısı yok. 3. adımda \"AI ile öner\", 4. adımda \"modelle skorla\" ya da "
                "\"Bu kaydı şimdi canlı skorla\", 6. adımda \"Planı AI ile açıkla\" modeli çalıştırır.")
        return

    basarili = [s for s in satirlar if s.get("ok")]
    c = st.columns(4)
    c[0].metric("Model çağrısı", len(satirlar))
    c[1].metric("Geçerli yanıt", f"{len(basarili)}/{len(satirlar)}")
    c[2].metric("Ortalama süre", f"{sum(s['sure_sn'] for s in satirlar) / len(satirlar):.1f} sn")
    c[3].metric("Yeniden sorma", sum(s.get("gecersiz_deneme", 0) for s in satirlar),
                help="Model geçersiz JSON ya da kapalı liste dışında bir değer döndürdüğünde soru yeniden "
                     "sorulur (en fazla 3 kez).")
    dagilim = Counter(s["islem"] for s in satirlar)
    st.caption(" · ".join(f"**{k}**: {v}" for k, v in dagilim.most_common()))

    islemler = ["Hepsi", *dagilim]
    filtre = st.segmented_control("İşlem", islemler, default="Hepsi", key="ai_iz_filtre",
                                  label_visibility="collapsed") or "Hepsi"
    gorunen = [s for s in reversed(satirlar) if filtre == "Hepsi" or s["islem"] == filtre]
    df = pd.DataFrame([{
        "Zaman": s["zaman"].replace("T", " "), "Adım": s.get("adim", ""), "İşlem": s["islem"],
        "Kayıt": s.get("kayit", ""), "Modelin cevabı": _ozet_yanit(s), "Süre (sn)": s["sure_sn"],
    } for s in gorunen])
    secim = st.dataframe(df, hide_index=True, use_container_width=True, height=min(60 + 35 * len(df), 320),
                         on_select="rerun", selection_mode="single-row", key="ai_iz_tablo",
                         column_config={"Modelin cevabı": st.column_config.TextColumn(width="large")})
    satir = secim.selection.rows[0] if secim and secim.selection.rows else 0
    s = gorunen[min(satir, len(gorunen) - 1)]

    st.markdown(f"**{s['islem']} · {s.get('kayit') or '-'}** · {s['zaman'].replace('T', ' ')} · "
                f"{s['sure_sn']} sn" + (f" · {s['gecersiz_deneme']} yeniden sorma" if s.get("gecersiz_deneme") else ""))
    st.caption("Tablodan bir satır seçin; modele giden prompt ve modelin yanıtı aşağıda.")
    k1, k2 = st.columns([3, 2])
    with k1:
        st.markdown("**Modele giden prompt**")
        st.code(s.get("prompt", ""), language=None, height=320)
    with k2:
        st.markdown("**Modelin yanıtı**")
        if s.get("yanit") is not None:
            st.json(s["yanit"])
        else:
            st.warning(s.get("hata") or "Yanıt yok.")
        if s.get("sayi_uyarisi"):
            st.caption("Sayı denetimi: metinde verilmeyen sayılar " + ", ".join(f"{x:g}" for x in s["sayi_uyarisi"]))
    st.download_button("AI izini indir (JSONL)", "\n".join(json.dumps(x, ensure_ascii=False) for x in satirlar),
                       file_name=f"ai_iz_{rdir.name if rdir else 'genel'}.jsonl", mime="application/json")
