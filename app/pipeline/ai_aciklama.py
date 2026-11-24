"""6. adım: seçilen önlem planının yerel modelle Türkçe açıklanması.

Model hesap yapmaz: bütün sayılar önlem motorundan (ai/onlem_secimi.py) gelir ve prompt'a
yazılır. Modelden yalnızca bunları okunur bir paragrafa dönüştürmesi istenir. Çıktıdaki her
sayı prompt'taki sayılarla karşılaştırılır; verilmeyen bir sayı yazılmışsa ekranda uyarı çıkar.
"""

import json
import math
import re
import urllib.error
import urllib.request

import time

from config import OLLAMA_URL
from pipeline import ai_iz

HEDEF_TR = {"node_target_admin": "yönetici erişimi", "node_target_rce": "kod çalıştırma",
            "node_target_account_takeover": "hesap ele geçirme", "node_target_leak": "veri sızıntısı",
            "node_target_dos": "hizmet kesintisi"}
KESINTI_TR = {"yok": "kesinti gerektirmez", "dusuk": "düşük kesinti riski", "var": "hizmet kesintisi gerektirir"}


def baglam(m, secim, guven, butce):
    """Modelin açıklayacağı olgular (yalnızca motorun hesapladıkları)."""
    taban = m.degerlendir(m.mevcut)
    s = m.senaryo(secim, guven)
    onlemler = []
    for o in m.katalog:
        if o["onlem_id"] not in secim:
            continue
        tek = m.senaryo([o["onlem_id"]], guven)
        onlemler.append({
            "kod": o["onlem_id"], "ad": o["ad"], "zafiyetler": o["hedefler"],
            "zafiyet_adlari": [m.adlar.get(v, v) for v in o["hedefler"]],
            "efor_saat": o["efor_saat"], "kesinti": KESINTI_TR.get(o["kesinti"], o["kesinti"]),
            "tek_basina_yol_riski_dususu": round(taban["yol_riski"] - tek["yol_riski"], 2),
        })
    kalan = []
    for y in m.yollar:
        risk = y["C"] * math.prod(p * (1 - s["etkinlik"].get(v, 0.0)) for p, v in zip(y["P"], y["zafiyetler"]))
        kalan.append((risk, y))
    kalan.sort(key=lambda x: -x[0])
    en_riskli = [{"yol": " -> ".join(n.replace("node_entry_", "giriş:").replace("node_target_", "hedef:")
                                     for n in y["yol"]),
                  "zafiyetler": [f"{v} ({m.adlar.get(v, v)})" for v in y["zafiyetler"]],
                  "hedef": HEDEF_TR.get(y["hedef"], y["hedef"]), "risk": round(r, 2)} for r, y in kalan[:3]]
    return {
        "butce_saat": butce, "harcanan_efor_saat": s["efor_saat"],
        "dayanak": "plan aşaması (gerekçe, engeller = 0.63)" if guven == "gerekce" else "test edilmiş varsayımı (engeller = 0.9)",
        "yol_riski_once": round(taban["yol_riski"], 2), "yol_riski_sonra": round(s["yol_riski"], 2),
        "yol_riski_dusus_yuzde": round((1 - s["yol_riski"] / taban["yol_riski"]) * 100, 1),
        "zafiyet_riski_once": round(taban["zafiyet_riski"], 2), "zafiyet_riski_sonra": round(s["zafiyet_riski"], 2),
        "kesilen_yol_once": taban["yol_durum"].get("kesildi", 0), "kesilen_yol_sonra": s["yol_durum"].get("kesildi", 0),
        "toplam_yol": len(m.yollar),
        "secilen_onlemler": onlemler,
        "kalan_en_riskli_yollar": en_riskli,
    }


def prompt(veri):
    return f"""Sen bir güvenlik danışmanısın. Aşağıdaki JSON, bir OWASP Juice Shop laboratuvarı için hesaplanmış
bir önlem planının sonuçlarıdır. Bu sonuçları yöneticiye anlatan Türkçe bir açıklama yaz.

Kurallar:
- Yalnızca JSON'daki bilgileri kullan. Hiçbir sayı uydurma, hesap yapma, yuvarlama dışında sayı değiştirme.
- 3 kısa paragraf, toplam en fazla 170 kelime:
  1) Plan ne kazandırıyor (yol riski önce/sonra ve düşüş yüzdesi, kesilen yol sayısı, harcanan efor).
  2) Hangi önlemler neden seçildi (en büyük katkıyı yapan 2-3 önlem, hangi zafiyetleri kapattığı, kesinti durumu).
  3) Plandan sonra kalan en riskli yol ve bir sonraki adım için tek cümlelik öneri.
- Sade dil kullan; zafiyet kodlarını (V022 gibi) parantez içinde ver.

Veri:
{json.dumps(veri, ensure_ascii=False, indent=1)}

Yalnızca şu JSON'u döndür: {{"aciklama": "<metin>"}}"""


def _sayilar(metin):
    return {float(x.replace(",", ".")) for x in re.findall(r"\d+(?:[.,]\d+)?", metin)}


def sayi_denetimi(metin, veri):
    """Metindeki sayılardan veride olmayanlar (V022 gibi kodlardaki numaralar dahil verilir)."""
    kaynak = _sayilar(json.dumps(veri, ensure_ascii=False))
    return sorted(x for x in _sayilar(metin) if x not in kaynak and not any(abs(x - k) < 0.051 for k in kaynak))


def acikla(veri, model, options, timeout=180, run_dir=None):
    """(metin, uyarı listesi) ya da (None, hata). Çağrı AI izine yazılır."""
    p, t0 = prompt(veri), time.time()
    istek = json.dumps({"model": model, "prompt": p, "stream": False, "format": "json",
                        "options": {**options, "num_predict": 700, "num_ctx": 8192}}).encode("utf-8")
    plan = ", ".join(o["kod"] for o in veri.get("secilen_onlemler", []))
    try:
        req = urllib.request.Request(f"{OLLAMA_URL}/api/generate", data=istek,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as yanit:
            govde = json.loads(yanit.read().decode("utf-8"))
        metin = json.loads(govde["response"])["aciklama"].strip()
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        hata = f"Ollama'ya ulaşılamadı: {e}"
        ai_iz.kaydet(run_dir, ai_iz.PLAN, plan, model, p, None, time.time() - t0, ok=False, hata=hata)
        return None, hata
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        hata = f"Model geçerli bir yanıt vermedi: {e}"
        ai_iz.kaydet(run_dir, ai_iz.PLAN, plan, model, p, None, time.time() - t0, ok=False, hata=hata)
        return None, hata
    uyari = sayi_denetimi(metin, veri)
    ai_iz.kaydet(run_dir, ai_iz.PLAN, plan, model, p, {"aciklama": metin}, time.time() - t0,
                 ek={"sayi_uyarisi": uyari})
    return metin, uyari
