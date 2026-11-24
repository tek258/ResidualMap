"""AI izi: uygulamanın yerel modele yaptığı her çağrının kaydı.

Her çağrı çalıştırmanın klasöründe `ai_iz.jsonl` dosyasına bir satır olarak eklenir: hangi adım,
hangi işlem, hangi kayıt, modele giden prompt, modelin yanıtı, süre, geçersiz deneme sayısı.
Çalıştırma açık değilken (6. adım çalıştırmasız da çalışır) kayıt `runs/_genel/ai_iz.jsonl`'a gider.
Arka plan işleri de buraya yazar; ekleme bir kilitle sırayla yapılır.
"""

import datetime
import json
import threading

from config import RUNS_DIR

DOSYA = "ai_iz.jsonl"
GENEL = RUNS_DIR / "_genel"
_KILIT = threading.Lock()

# Uygulamadaki AI işlemleri (adım, işlem): Özet'teki şerit ve AI izi penceresi bu adları kullanır
SKOR, SKOR_TEK, BAGLANTI, PLAN = "Risk skoru", "Risk skoru (canlı, tek kayıt)", "Grafiğe bağlantı önerisi", "Plan açıklaması"
ADIM = {SKOR: "4. Grafik", SKOR_TEK: "4. Grafik", BAGLANTI: "3. Bulgular", PLAN: "6. Önlem seçimi"}


def _yol(run_dir):
    return (run_dir if run_dir else GENEL) / DOSYA


def kaydet(run_dir, islem, kayit, model, prompt, yanit, sure_sn, ok=True, hata="", gecersiz=0, ek=None):
    """Bir model çağrısını ekler. Kayıt hatası uygulamayı durdurmaz."""
    satir = {
        "zaman": datetime.datetime.now().isoformat(timespec="seconds"),
        "adim": ADIM.get(islem, ""), "islem": islem, "kayit": kayit or "", "model": model,
        "ok": bool(ok), "sure_sn": round(float(sure_sn), 2), "gecersiz_deneme": int(gecersiz),
        "yanit": yanit, "hata": hata or "", "prompt": prompt, **(ek or {}),
    }
    try:
        yol = _yol(run_dir)
        yol.parent.mkdir(parents=True, exist_ok=True)
        with _KILIT, open(yol, "a", encoding="utf-8") as f:
            f.write(json.dumps(satir, ensure_ascii=False) + "\n")
    except OSError:
        pass


def oku(run_dir):
    yol = _yol(run_dir)
    if not yol.exists():
        return []
    satirlar = []
    with open(yol, encoding="utf-8") as f:
        for s in f:
            try:
                satirlar.append(json.loads(s))
            except ValueError:      # o an yazılmakta olan son satır
                pass
    return satirlar


def sayi(run_dir):
    """Hızlı sayım (yan menü her çizimde çağırır)."""
    yol = _yol(run_dir)
    if not yol.exists():
        return 0
    with open(yol, "rb") as f:
        return sum(1 for _ in f)
