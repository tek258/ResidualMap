"""Uygulama ayarları ve izin verilen lab hedefleri."""

from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNS_DIR = REPO_ROOT / "runs"                  # her çalıştırmanın klasörü (gitignore'da)
RAW_DIR = REPO_ROOT / "inventory" / "raw"      # mevcut ham tarama dosyaları
FROZEN_INVENTORY = REPO_ROOT / "inventory" / "inventory_v1.0.csv"   # dondurulmuş envanter
GRAPH_DIR = REPO_ROOT / "graph"                # generate_edges / find_paths / visualize_graph
FETCH_SCORES = REPO_ROOT / "ai" / "fetch_scores.py"          # NVD / FIRST EPSS sorguları
SCORES_CACHE = REPO_ROOT / "ai" / "cvss_epss_scores.csv"     # fetch_scores.py'nin çıktısı (önbellek)
AI_DIR = REPO_ROOT / "ai"                      # model_v2_local_llm.py, results_v2_llm.csv
OLLAMA_URL = "http://localhost:11434"          # yerel LLM (model v2)

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
        "imaj": "bkimminich/juice-shop:v20.2.0",        # Trivy imaj taraması (compose ile aynı sürüm)
        "zap_url": "http://host.docker.internal:8080",  # ZAP konteynerinden erişilen adres
        "tarayici_url": "http://localhost:8080",        # tarayıcıdan erişilen adres
    },
}

# --- Savunma panosu (Grafana, defense/ klasöründe `docker compose --profile siem up -d`) ---
# Uygulama Grafana'ya yalnızca bağlantı verir; panoyu Grafana kendi sekmesinde gösterir.
GRAFANA_URL = "http://localhost:3001"
GRAFANA_PANO = GRAFANA_URL + "/d/residualmap-lab"   # siem/grafana/dashboards/residualmap-lab.json (uid)

# Hedef adresleri yalnızca yerel olabilir; listeye yanlışlıkla dış bir adres
# eklenirse uygulama hiç açılmaz.
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "host.docker.internal"}


def _check_targets():
    for ad, url in (("GRAFANA_URL", GRAFANA_URL), ("OLLAMA_URL", OLLAMA_URL)):
        if urlparse(url).hostname not in ALLOWED_HOSTS:
            raise ValueError(f"{ad} yerel bir adres değil: {url}")
    for key, target in TARGETS.items():
        for alan in ("zap_url", "tarayici_url"):
            host = urlparse(target[alan]).hostname
            if host not in ALLOWED_HOSTS:
                raise ValueError(
                    f"TARGETS['{key}']['{alan}'] yerel bir lab adresi değil: {target[alan]}"
                )


_check_targets()
