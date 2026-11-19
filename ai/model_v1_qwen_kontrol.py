"""[S4][K4] Kontrol çalıştırması: v1'in prompt'u ve ayarları, yalnızca model qwen2.5:7b.

v1 -> v2 arasında hem model hem prompt değişiyor. Bu çalıştırma ikisini ayırır:
    v1 (phi3)  -> v1-qwen : modelin katkısı
    v1-qwen    -> v2      : prompt'un katkısı

model_v1_local_llm.py değiştirilmez, yalnızca içe aktarılır.

Kullanım (repo kökünden, Ollama açıkken):
    python ai/model_v1_qwen_kontrol.py

Çıktı:
    ai/results_v1_qwen_llm.csv
"""

import importlib.util
import os

AI_DIR = os.path.dirname(os.path.abspath(__file__))

spec = importlib.util.spec_from_file_location("model_v1", os.path.join(AI_DIR, "model_v1_local_llm.py"))
v1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v1)

v1.MODEL_NAME = "qwen2.5:7b"  # prompt, temperature 0.1 ve num_ctx 2048 v1 ile aynı kalır

if __name__ == "__main__":
    v1.score_vulnerabilities("inventory/inventory_v1.0.csv", "ai/results_v1_qwen_llm.csv")
