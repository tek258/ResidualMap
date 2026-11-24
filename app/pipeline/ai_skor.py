"""AI risk skoru (model v2) için çalıştırma düzeyinde skor dosyası.

Her çalıştırmanın kendi skor dosyası vardır: runs/<id>/ai_skorlari.csv
  - Dondurulmuş envanterde de bulunan kayıtlar (aynı vuln_id ve ad) skorunu hazır
    sonuçtan (ai/results_v2_llm.csv) alır: Ollama gerekmez.
  - Yeni kayıtlar Ollama açıksa model v2 ile skorlanır. Model kodu yeniden yazılmaz;
    ai/model_v2_local_llm.py'deki prompt ve sorgu fonksiyonları çağrılır.
"""

import csv
import importlib.util
import json
import time
import urllib.error
import urllib.request

from config import AI_DIR, FROZEN_INVENTORY, OLLAMA_URL
from pipeline import dosya

HAZIR_SONUC = AI_DIR / "results_v2_llm.csv"
MODEL_SCRIPT = AI_DIR / "model_v2_local_llm.py"
DOSYA = "ai_skorlari.csv"
ALANLAR = ["vuln_id", "risk_score_llm", "risk_label_llm", "llm_reason", "kaynak"]
HAZIR, MODEL = "hazır sonuç", "model (bu çalıştırma)"


def _oku(path):
    if not path.exists():
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _yaz(path, satirlar):
    with dosya.atomik(path, newline="") as f:
        w = csv.DictWriter(f, fieldnames=ALANLAR)
        w.writeheader()
        w.writerows(sorted(satirlar, key=lambda r: r["vuln_id"]))


def model_modulu():
    spec = importlib.util.spec_from_file_location("residualmap_model_v2", MODEL_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ollama_durumu(timeout=2):
    """(ok, mesaj, model_adı). Ollama yerel adreste mi, model v2'nin modeli yüklü mü?"""
    if not MODEL_SCRIPT.exists():
        return False, f"{MODEL_SCRIPT.name} bulunamadı.", None
    model = model_modulu().MODEL_NAME
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=timeout) as r:
            yuklu = {m["name"] for m in json.loads(r.read().decode("utf-8")).get("models", [])}
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False, "Ollama çalışmıyor. Model ile skorlamak için Ollama'yı başlatın.", model
    if model not in yuklu:
        return False, f"Ollama açık ama `{model}` modeli yüklü değil: `ollama pull {model}`", model
    return True, f"Ollama açık, model: `{model}`.", model


def hazirla(run_dir):
    """Çalıştırmanın skor dosyasını günceller ve yolunu döndürür.

    Hazır sonuçtan gelebilecek skorlar doldurulur; daha önce bu çalıştırmada model ile
    üretilmiş skorlar korunur; envanterden çıkmış kayıtların skorları silinir.
    """
    inv = {r["vuln_id"]: r for r in _oku(run_dir / "inventory.csv")}
    donmus = {r["vuln_id"]: r for r in _oku(FROZEN_INVENTORY)}
    hazir = {r["vuln_id"]: r for r in _oku(HAZIR_SONUC)}
    mevcut = {r["vuln_id"]: r for r in _oku(run_dir / DOSYA)}

    satirlar = []
    for vid, row in inv.items():
        if mevcut.get(vid, {}).get("kaynak") == MODEL:
            satirlar.append(mevcut[vid])
        elif vid in hazir and donmus.get(vid, {}).get("name") == row.get("name"):
            h = hazir[vid]
            satirlar.append({"vuln_id": vid, "risk_score_llm": h["risk_score_llm"],
                             "risk_label_llm": h.get("risk_label_llm", ""),
                             "llm_reason": h.get("llm_reason", ""), "kaynak": HAZIR})
    _yaz(run_dir / DOSYA, satirlar)
    return run_dir / DOSYA


def skorla(run_dir, hepsi=False, on_progress=None, iptal=None):
    """Eksik (hepsi=True ise tüm) kayıtları model v2 ile skorlar. Sonuç özetini döndürür.
    iptal() True dönerse sıradaki kayda geçmeden durur; o ana kadarki skorlar kaydedilmiştir."""
    m = model_modulu()
    inv = {r["vuln_id"]: r for r in _oku(run_dir / "inventory.csv")}
    # Few-shot örnekleri (V023, V006, V019) dondurulmuş envanterden gelir; yeni bir taramanın
    # envanterinde bulunmayabilirler.
    envanter = {**{r["vuln_id"]: r for r in _oku(FROZEN_INVENTORY)}, **inv}
    mevcut = {r["vuln_id"]: r for r in _oku(hazirla(run_dir))}
    hedef = [v for v in inv if hepsi or v not in mevcut]

    basarisiz, gecersiz, t0 = [], 0, time.time()
    for i, vid in enumerate(hedef, start=1):
        if iptal and iptal():
            hedef = hedef[:i - 1]
            break
        if on_progress:
            on_progress(i - 1, len(hedef), vid)
        skor, gerekce, g, _ = m.sor(m.prompt_olustur(inv[vid], envanter), vid, m.MODEL_NAME)
        gecersiz += g
        if skor is None:
            basarisiz.append(vid)
            continue
        mevcut[vid] = {"vuln_id": vid, "risk_score_llm": skor, "risk_label_llm": m.sinif(skor),
                       "llm_reason": gerekce, "kaynak": MODEL}
        _yaz(run_dir / DOSYA, mevcut.values())   # her kayıttan sonra: yarıda kalırsa kaybolmasın
    if on_progress:
        on_progress(len(hedef), len(hedef), "")
    return {"skorlanan": len(hedef) - len(basarisiz), "basarisiz": basarisiz,
            "gecersiz_deneme": gecersiz, "sure_sn": round(time.time() - t0, 1), "model": m.MODEL_NAME}


def skorla_tek(run_dir, vid):
    """Tek kaydı model v2 ile skorlar (demoda canlı gösterim). Dönüş: (skor, sınıf, gerekçe, süre_sn)
    ya da skor None ise hata."""
    m = model_modulu()
    inv = {r["vuln_id"]: r for r in _oku(run_dir / "inventory.csv")}
    envanter = {**{r["vuln_id"]: r for r in _oku(FROZEN_INVENTORY)}, **inv}
    mevcut = {r["vuln_id"]: r for r in _oku(hazirla(run_dir))}
    t0 = time.time()
    skor, gerekce, _, _ = m.sor(m.prompt_olustur(inv[vid], envanter), vid, m.MODEL_NAME)
    sure = round(time.time() - t0, 1)
    if skor is None:
        return None, None, None, sure
    mevcut[vid] = {"vuln_id": vid, "risk_score_llm": skor, "risk_label_llm": m.sinif(skor),
                   "llm_reason": gerekce, "kaynak": MODEL}
    _yaz(run_dir / DOSYA, mevcut.values())
    return skor, m.sinif(skor), gerekce, sure


def modele_giden(run_dir, vid):
    """(kanıt metni, tam prompt): modelin bu kayıt için gördüğü her şey."""
    m = model_modulu()
    inv = {r["vuln_id"]: r for r in _oku(run_dir / "inventory.csv")}
    envanter = {**{r["vuln_id"]: r for r in _oku(FROZEN_INVENTORY)}, **inv}
    return m.bulgu_metni(inv[vid]), m.prompt_olustur(inv[vid], envanter), m.MODEL_NAME


def tablo(run_dir):
    """CVSS ve AI sıralamasını yan yana veren satırlar (AI skoru olmayanlar sonda)."""
    inv = _oku(run_dir / "inventory.csv")
    ai = {r["vuln_id"]: r for r in _oku(run_dir / DOSYA)}

    def _f(x):
        try:
            return float(x)
        except (TypeError, ValueError):
            return None

    cvss = {r["vuln_id"]: _f(r.get("cvss_score")) for r in inv}
    skor = {v: _f(r["risk_score_llm"]) for v, r in ai.items()}

    def sira(d):
        # eşit skorlar aynı sırayı alır (baseline_ranking.py ile aynı mantık)
        degerler = sorted((s for s in d.values() if s is not None), reverse=True)
        return {v: degerler.index(s) + 1 for v, s in d.items() if s is not None}

    cvss_sira, ai_sira = sira(cvss), sira(skor)
    satirlar = [{
        "Kayıt": r["vuln_id"], "Ad": r.get("name", ""),
        "CVSS": cvss[r["vuln_id"]], "CVSS sırası": cvss_sira.get(r["vuln_id"]),
        "AI skoru": skor.get(r["vuln_id"]), "AI sırası": ai_sira.get(r["vuln_id"]),
        "AI sınıfı": ai.get(r["vuln_id"], {}).get("risk_label_llm") or "-",
        "Kaynak": ai.get(r["vuln_id"], {}).get("kaynak") or "yok",
        "AI gerekçesi": ai.get(r["vuln_id"], {}).get("llm_reason", ""),
    } for r in inv]
    return sorted(satirlar, key=lambda s: (s["AI sırası"] is None, s["AI sırası"] or 0, s["CVSS sırası"] or 999))
