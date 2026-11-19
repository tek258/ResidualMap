"""2. adım: ham verinin toplanması.

Üç kaynak var: ZAP baseline (web), Trivy (konteyner imajı), Juice Shop
challenge listesi. Her kaynak ya canlı olarak toplanır ya da mevcut bir
dosyadan yüklenir. Sonuç her zaman runs/<id>/raw/<dosya> olarak kaydedilir.

Güvenlik: komutlar her zaman argüman listesi olarak çalışır (kabuk yok), hedef
bilgileri yalnızca config.TARGETS'tan gelir.
"""

import json
import shutil
import subprocess
import time
import urllib.request
from dataclasses import dataclass, field

from config import RAW_DIR

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
TRIVY_IMAGE = "aquasec/trivy:latest"

RAW_FILES = {
    "zap": "zap_baseline.json",
    "trivy": "trivy.json",
    "challenges": "challenges.json",
}
KAYNAK_ADLARI = {
    "zap": "ZAP baseline (web taraması)",
    "trivy": "Trivy (imaj taraması)",
    "challenges": "Juice Shop challenge listesi",
}

ZAP_TIMEOUT = 15 * 60
TRIVY_TIMEOUT = 20 * 60      # ilk çalıştırmada zafiyet veritabanı indirilir


@dataclass
class Sonuc:
    ok: bool
    mesaj: str
    sure: float = 0.0
    ozet: dict = field(default_factory=dict)


# --- Özetler: dosya geçerli mi, içinde kaç bulgu var ---

def ozetle(kaynak, path):
    """Ham dosyayı okur, bulgu sayılarını döndürür. Bozuksa ValueError."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"Geçerli bir JSON dosyası değil: {e}")

    if kaynak == "zap":
        if "site" not in data:
            raise ValueError("ZAP raporu değil ('site' alanı yok)")
        alerts = [a for s in data["site"] for a in s.get("alerts", [])]
        risk = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}
        dagilim = {}
        for a in alerts:
            ad = risk.get(str(a.get("riskcode")), "?")
            dagilim[ad] = dagilim.get(ad, 0) + 1
        ornek = sum(len(a.get("instances", [])) for a in alerts)
        return {"bulgu türü": len(alerts), "örnek": ornek, **dagilim}

    if kaynak == "trivy":
        if "Results" not in data:
            raise ValueError("Trivy raporu değil ('Results' alanı yok)")
        vulns = [v for r in data["Results"] for v in (r.get("Vulnerabilities") or [])]
        dagilim = {}
        for v in vulns:
            s = v.get("Severity", "UNKNOWN")
            dagilim[s] = dagilim.get(s, 0) + 1
        sira = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        return {"zafiyet": len(vulns), "imaj": data.get("ArtifactName", "?"),
                **{k: dagilim[k] for k in sira if k in dagilim}}

    if kaynak == "challenges":
        items = data.get("data") if isinstance(data, dict) else data
        if not isinstance(items, list) or not items or "name" not in items[0]:
            raise ValueError("Challenge listesi değil (beklenen: {'data': [...]})")
        return {"challenge": len(items),
                "kategori": len({c.get("category") for c in items})}

    raise ValueError(f"Bilinmeyen kaynak: {kaynak}")


# --- Mevcut dosyadan yükleme ---

def repo_dosyasi(kaynak):
    return RAW_DIR / RAW_FILES[kaynak]


def yukle_repodan(kaynak, raw_dir):
    src = repo_dosyasi(kaynak)
    if not src.exists():
        return Sonuc(False, f"{src} bulunamadı.")
    return _kaydet_ve_ozetle(kaynak, raw_dir, lambda dst: shutil.copyfile(src, dst),
                             f"inventory/raw/{RAW_FILES[kaynak]} yüklendi.")


def yukle_bayttan(kaynak, raw_dir, icerik):
    return _kaydet_ve_ozetle(kaynak, raw_dir, lambda dst: dst.write_bytes(icerik),
                             "Yüklenen dosya kaydedildi.")


def _kaydet_ve_ozetle(kaynak, raw_dir, yaz, mesaj, sure=0.0):
    dst = raw_dir / RAW_FILES[kaynak]
    yaz(dst)
    try:
        ozet = ozetle(kaynak, dst)
    except ValueError as e:
        dst.unlink(missing_ok=True)
        return Sonuc(False, str(e), sure)
    return Sonuc(True, mesaj, sure, ozet)


# --- Canlı toplama ---

def _calistir(cmd, timeout, on_line, stdout_dosyasi=None):
    """Komutu çalıştırır, çıktıyı satır satır on_line'a iletir.

    stdout_dosyasi verilirse standart çıktı o dosyaya yazılır (Trivy JSON'u),
    ekrana yalnızca hata akışı gelir.
    """
    baslangic = time.time()
    out = open(stdout_dosyasi, "wb") if stdout_dosyasi else None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=out if out else subprocess.PIPE,
            stderr=subprocess.PIPE if out else subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
        )
    except FileNotFoundError:
        if out:
            out.close()
        raise RuntimeError("Docker komutu bulunamadı.")
    akis = proc.stderr if out else proc.stdout
    try:
        for line in akis:
            on_line(line.rstrip())
            if time.time() - baslangic > timeout:
                proc.kill()
                raise RuntimeError(f"Zaman aşımı ({timeout // 60} dk).")
        proc.wait()
    finally:
        if out:
            out.close()
    return proc.returncode, time.time() - baslangic


def tara_zap(target, raw_dir, on_line):
    """ZAP baseline: pasif tarama, hedefe saldırı isteği göndermez."""
    cmd = [
        "docker", "run", "--rm",
        # Linux'ta host.docker.internal tanımlı değil; Docker Desktop'ta zararsız
        "--add-host=host.docker.internal:host-gateway",
        "-v", f"{raw_dir.resolve()}:/zap/wrk:rw",
        ZAP_IMAGE, "zap-baseline.py",
        "-t", target["zap_url"],
        "-J", RAW_FILES["zap"],
    ]
    try:
        kod, sure = _calistir(cmd, ZAP_TIMEOUT, on_line)
    except RuntimeError as e:
        return Sonuc(False, str(e))
    # zap-baseline çıkış kodları: 0 temiz, 1 FAIL, 2 WARN bulgusu var, 3 hata
    if kod == 3 or not (raw_dir / RAW_FILES["zap"]).exists():
        return Sonuc(False, f"ZAP taraması başarısız (çıkış kodu {kod}). Günlüğe bakın.", sure)
    return _kaydet_ve_ozetle("zap", raw_dir, lambda dst: None, "ZAP taraması tamamlandı.", sure)


def tara_trivy(target, raw_dir, on_line):
    """Trivy: imajdaki paketlerin bilinen zafiyetlerini listeler."""
    cmd = [
        "docker", "run", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "residualmap-trivy-cache:/root/.cache/",   # veritabanı her seferinde inmesin
        TRIVY_IMAGE, "image",
        "--scanners", "vuln",
        "--format", "json",
        target["imaj"],
    ]
    dst = raw_dir / RAW_FILES["trivy"]
    try:
        kod, sure = _calistir(cmd, TRIVY_TIMEOUT, on_line, stdout_dosyasi=dst)
    except RuntimeError as e:
        return Sonuc(False, str(e))
    if kod != 0:
        dst.unlink(missing_ok=True)
        return Sonuc(False, f"Trivy taraması başarısız (çıkış kodu {kod}). Günlüğe bakın.", sure)
    return _kaydet_ve_ozetle("trivy", raw_dir, lambda d: None, "Trivy taraması tamamlandı.", sure)


def al_challenges(target, raw_dir, on_line):
    """Juice Shop'un kendi API'sinden challenge listesini alır."""
    url = target["tarayici_url"].rstrip("/") + "/api/Challenges/"
    on_line(f"GET {url}")
    baslangic = time.time()
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            icerik = resp.read()
    except OSError as e:
        return Sonuc(False, f"Challenge listesi alınamadı: {e}")
    return _kaydet_ve_ozetle("challenges", raw_dir, lambda dst: dst.write_bytes(icerik),
                             "Challenge listesi alındı.", time.time() - baslangic)


CANLI = {"zap": tara_zap, "trivy": tara_trivy, "challenges": al_challenges}
