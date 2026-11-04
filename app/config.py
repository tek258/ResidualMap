"""Uygulama ayarları ve izin verilen lab hedefleri."""

from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = REPO_ROOT / "runs"                  # her çalıştırmanın klasörü (gitignore'da)
RAW_DIR = REPO_ROOT / "inventory" / "raw"      # mevcut ham tarama dosyaları
FROZEN_INVENTORY = REPO_ROOT / "inventory" / "inventory_v1.0.csv"   # dondurulmuş envanter

# --- İzin verilen hedefler ---
# Uygulama YALNIZCA bu listedeki hedefleri tarar. Arayüzde serbest adres girme
# alanı yoktur. Buraya sadece kendi makinemizdeki lab ağında çalışan, kasıtlı
# olarak açıklı uygulamalar eklenir.
TARGETS = {
    "juice-shop": {
        "ad": "OWASP Juice Shop",
        "aciklama": "Kasıtlı olarak açıklı eğitim uygulaması. "
                    "Lab ortamında WAF (nginx + ModSecurity) arkasında çalışıyor.",
        "konteyner": "juice-shop",                      # docker-compose.yml: container_name
        "imaj": "bkimminich/juice-shop",                # Trivy imaj taraması
        "zap_url": "http://host.docker.internal:8080",  # ZAP konteynerinden erişilen adres
        "tarayici_url": "http://localhost:8080",        # tarayıcıdan erişilen adres
    },
}

# Hedef adresleri yalnızca yerel olabilir; listeye yanlışlıkla dış bir adres
# eklenirse uygulama hiç açılmaz.
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "host.docker.internal"}


def _check_targets():
    for key, target in TARGETS.items():
        for alan in ("zap_url", "tarayici_url"):
            host = urlparse(target[alan]).hostname
            if host not in ALLOWED_HOSTS:
                raise ValueError(
                    f"TARGETS['{key}']['{alan}'] yerel bir lab adresi değil: {target[alan]}"
                )


_check_targets()
