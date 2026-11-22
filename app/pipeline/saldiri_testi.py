"""Lab'ın WAF doğrulama testini (defense/test-waf.sh) uygulamadan çalıştırır.

Test betiği yeniden yazılmaz, bash ile çağrılır. Uygulama adres ya da yük girişi
almaz: betik yalnızca config'deki izinli hedefin tarayıcı adresine (localhost:8080),
betikte sabit tanımlı istekleri gönderir.
"""

import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from config import REPO_ROOT

BETIK = REPO_ROOT / "defense" / "test-waf.sh"
# İki satır biçimi: "etiket -> HTTP 403  (beklenen 403) OK" (istek satırları) ve
# "etiket -> <ayrıntı> OK" (başlık, hata sayfası, hız sınırı kontrolleri).
SATIR_RE = re.compile(r"^(?P<etiket>.*?)\s+-> (?P<detay>.*?)\s(?P<durum>OK|HATA)\s*$")
KOD_RE = re.compile(r"HTTP (?P<kod>\d{3})")
BEK_RE = re.compile(r"\(beklenen (?P<bek>\d{3})\)")
BOLUM_RE = re.compile(r"^== (?P<ad>.+?) ==$")
ZAFIYET_RE = re.compile(r"\bV\d{3}\b")
# Etiketinde kayıt numarası olmayan satırlar: S5-K2 README'sindeki eşleme
ETIKET_ZAFIYET = {"SQLi": "V002"}


@dataclass
class Sonuc:
    ok: bool
    mesaj: str
    satirlar: list = field(default_factory=list)
    cikti: str = ""
    sure: float = 0.0


def bash_bul():
    """Git Bash'i bulur. Windows'taki WSL bash'i (System32) bilerek kullanılmaz: istekler
    WSL'in içinden gider ve localhost davranışı farklı olabilir."""
    if sys.platform != "win32":
        return shutil.which("bash")
    adaylar = []
    for degisken in ("ProgramFiles", "ProgramFiles(x86)", "LocalAppData"):
        kok = os.environ.get(degisken)
        if kok:
            adaylar += [Path(kok) / "Git" / "bin" / "bash.exe",
                        Path(kok) / "Programs" / "Git" / "bin" / "bash.exe"]
    git = shutil.which("git")
    if git:   # ...\Git\cmd\git.exe -> ...\Git\bin\bash.exe
        adaylar.append(Path(git).resolve().parents[1] / "bin" / "bash.exe")
    for p in adaylar:
        if p.exists():
            return str(p)
    return None


def hazir_mi():
    """(ok, mesaj)"""
    if not BETIK.exists():
        return False, f"Test betiği bulunamadı: {BETIK.relative_to(REPO_ROOT)}"
    if not bash_bul():
        return False, ("Git Bash bulunamadı. Test betiği bash ile çalışıyor; Windows'ta "
                       "Git for Windows kurulu olmalı.")
    return True, "Hazır."


def ayristir(cikti):
    """test-waf.sh çıktısını satırlara ayırır: bölüm, etiket, zafiyet, kod, beklenen, durum."""
    bolum, satirlar = "", []
    for line in cikti.splitlines():
        m = BOLUM_RE.match(line.strip())
        if m:
            bolum = m["ad"]
            continue
        m = SATIR_RE.match(line.rstrip())
        if m:
            km, bm = KOD_RE.search(m["detay"]), BEK_RE.search(m["detay"])
            kod = km["kod"] if km else None
            vid = ZAFIYET_RE.search(m["etiket"])
            if bm:   # istek satırı
                sonuc = ("engellendi (WAF)" if kod == "403" else "sınırlandı (429)" if kod == "429"
                         else "geçti" if kod and kod.startswith(("2", "3", "4")) else "hata")
            else:    # kontrol satırı: ayrıntı olduğu gibi (başlık değeri, 429 sayısı, yığın izi)
                sonuc = re.sub(r"\s+", " ", m["detay"]).strip()[:70]
            satirlar.append({
                "Bölüm": bolum,
                "İstek": m["etiket"].strip(),
                "Zafiyet": vid.group(0) if vid else ETIKET_ZAFIYET.get(m["etiket"].strip(), "-"),
                "HTTP": int(kod) if kod else None,
                "Beklenen": int(bm["bek"]) if bm else None,
                "Sonuç": sonuc,
                "Durum": "✅" if m["durum"] == "OK" else "❌",
            })
    return satirlar


def calistir(target, timeout=120):
    ok, mesaj = hazir_mi()
    if not ok:
        return Sonuc(False, mesaj)
    t0 = time.time()
    try:
        r = subprocess.run([bash_bul(), BETIK.name, target["tarayici_url"]], cwd=BETIK.parent,
                           capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return Sonuc(False, f"Test {timeout} sn içinde bitmedi.", sure=time.time() - t0)
    satirlar = ayristir(r.stdout)
    if not satirlar:
        return Sonuc(False, "Test çıktısı okunamadı.", cikti=r.stdout + r.stderr, sure=time.time() - t0)
    beklenmeyen = sum(s["Durum"] == "❌" for s in satirlar)
    engellenen = sum(s["HTTP"] == 403 for s in satirlar)
    mesaj = (f"{len(satirlar)} kontrol: {engellenen} saldırı isteği WAF tarafından engellendi, "
             f"{beklenmeyen} beklenmeyen sonuç.")
    return Sonuc(beklenmeyen == 0, mesaj, satirlar, r.stdout, time.time() - t0)
