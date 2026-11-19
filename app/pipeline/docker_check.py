"""Docker ve hedef konteynerin durumunu kontrol eder."""

import subprocess
from dataclasses import dataclass


@dataclass
class Durum:
    ok: bool
    mesaj: str


def _docker(args, timeout):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def docker_durumu(timeout=8):
    try:
        r = _docker(["version", "--format", "{{.Server.Version}}"], timeout)
    except FileNotFoundError:
        return Durum(False, "Docker komutu bulunamadı. Docker Desktop kurulu mu?")
    except subprocess.TimeoutExpired:
        return Durum(False, "Docker yanıt vermedi (zaman aşımı).")
    if r.returncode != 0:
        return Durum(False, "Docker çalışmıyor. Docker Desktop'ı başlatın.")
    return Durum(True, f"Docker çalışıyor (sürüm {r.stdout.strip()}).")


def konteyner_durumu(ad, timeout=8):
    try:
        r = _docker(["inspect", "-f", "{{.State.Running}}", ad], timeout)
    except FileNotFoundError:
        return Durum(False, "Docker komutu bulunamadı.")
    except subprocess.TimeoutExpired:
        return Durum(False, "Docker yanıt vermedi (zaman aşımı).")
    if r.returncode != 0:
        return Durum(False, f"'{ad}' konteyneri yok. Lab ortamını başlatın: "
                            "defense/ klasöründe `docker compose up -d`.")
    if r.stdout.strip() != "true":
        return Durum(False, f"'{ad}' konteyneri var ama çalışmıyor: `docker start {ad}`.")
    return Durum(True, f"'{ad}' konteyneri çalışıyor.")


def grafana_durumu(url, timeout=2):
    """Grafana'nın sağlık uç noktasını sorgular (yalnızca yerel adres, config'de denetleniyor)."""
    import json
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(f"{url}/api/health", timeout=timeout) as r:
            veri = json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return Durum(False, "Savunma panosu kapalı. Açmak için defense/ klasöründe: "
                            "`docker compose --profile siem up -d`")
    if veri.get("database") != "ok":
        return Durum(False, "Grafana açılıyor, birkaç saniye sonra yenileyin.")
    return Durum(True, f"Savunma panosu açık (Grafana {veri.get('version', '?')}).")
