#!/usr/bin/env python3
"""
[S1][K4] Ollama deneme scripti

ai/features.csv'nin ilk N kaydını yerel Ollama modeline gönderir, her kayıt
için JSON formatında risk skoru ister ve:
  - yanıtın JSON olarak parse edilip edilemediğini,
  - her kaydın kaç saniye sürdüğünü
ekrana yazar. Bu sadece bir denemedir; tam model S2'de yazılacak.

Kullanım (repo kök dizininden, Ollama açıkken):
    python ai/ollama_deneme.py                          # varsayılan: İngilizce prompt
    python ai/ollama_deneme.py --dil tr                 # Türkçe prompt (karşılaştırma için)
    python ai/ollama_deneme.py --model llama3.1:8b --n 5
"""

import argparse
import csv
import json
import time
import urllib.error
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/generate"

# İngilizce prompt varsayılan: küçük modeller (phi3:mini vb.) Türkçe talimatta
# formattan sapıyor, kendini tekrar ediyor ve token sınırına takılıyordu
# (S1 denemesi: 5 kayıttan 3'ü yarıda kesilmiş JSON).
PROMPT_EN = """You are a security analyst prioritizing vulnerabilities in a web
application. Give a risk score for the vulnerability below.

Vulnerability:
- Name: {name}
- CWE: {cwe_id}
- CVSS v3.1 base score: {cvss_score}
- EPSS score (exploitation probability, 0-1): {epss_score}
- Attack vector: {attack_vector}
- Attack complexity: {attack_complexity}
- Authentication required: {auth_required}
- User interaction required: {user_interaction}
- Asset criticality (1-5): {asset_criticality}
- Exposure: {exposure}

Return only JSON in exactly this format, nothing else:
{{"risk_score": <number between 0 and 10>, "reason": "<one sentence, at most 25 words>"}}
"""

PROMPT_TR = """Sen bir güvenlik analistisin. Aşağıdaki zafiyetin bir web
uygulaması için önceliklendirme amaçlı risk skorunu ver.

Zafiyet:
- Ad: {name}
- CWE: {cwe_id}
- CVSS v3.1 skoru: {cvss_score}
- EPSS skoru (sömürülme olasılığı, 0-1): {epss_score}
- Saldırı vektörü: {attack_vector}
- Saldırı karmaşıklığı: {attack_complexity}
- Kimlik doğrulama gerekli mi: {auth_required}
- Kullanıcı etkileşimi gerekli mi: {user_interaction}
- Varlık kritikliği (1-5): {asset_criticality}
- Erişilebilirlik: {exposure}

Yalnızca şu formatta JSON döndür, başka hiçbir şey yazma:
{{"risk_score": <0 ile 10 arası sayı>, "reason": "<tek cümle, en fazla 25 kelime>"}}
"""


def ollama_sor(model, prompt, timeout, num_ctx, num_predict):
    """Ollama'ya tek bir istek gönderir, ham yanıt metnini döndürür."""
    body = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",              # modeli geçerli JSON üretmeye zorlar
        "options": {
            "temperature": 0,          # aynı girdiye mümkün olduğunca aynı çıktı
            # Bağlam penceresi: prompt ~300 token, yanıt ~100 token; 2048 yeter.
            # Küçük tutmak bellek kullanımını belirgin şekilde azaltır
            # (llama3.1:8b'nin bellek yüzünden çökmesini önleyebilir).
            "num_ctx": num_ctx,
            # Üretilecek en fazla token. Çok düşük olursa JSON yarıda kesilir
            # ve parse edilemez; 200 Türkçe yanıtlar için yetmedi.
            "num_predict": num_predict,
            # Modelin aynı cümleyi tekrar etmesini azaltır.
            "repeat_penalty": 1.2,
        },
    }).encode("utf-8")
    req = urllib.request.Request(
        OLLAMA_URL, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))["response"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default="ai/features.csv")
    ap.add_argument("--model", default="qwen2.5:7b")
    ap.add_argument("--n", type=int, default=5)
    ap.add_argument("--dil", choices=["en", "tr"], default="en")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--num-ctx", type=int, default=2048)
    ap.add_argument("--num-predict", type=int, default=400)
    args = ap.parse_args()

    sablon = PROMPT_EN if args.dil == "en" else PROMPT_TR
    bilinmiyor = "unknown" if args.dil == "en" else "bilinmiyor"

    with open(args.features, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))[: args.n]

    basarili, hatali, sureler = 0, 0, []
    cvss_ile_ayni = 0

    for r in rows:
        alanlar = {k: (r.get(k) or bilinmiyor) for k in [
            "name", "cwe_id", "cvss_score", "epss_score", "attack_vector",
            "attack_complexity", "auth_required", "user_interaction",
            "asset_criticality", "exposure"]}
        prompt = sablon.format(**alanlar)

        baslangic = time.time()
        try:
            ham = ollama_sor(args.model, prompt, args.timeout,
                             args.num_ctx, args.num_predict)
        except urllib.error.HTTPError as e:
            # Ollama'nın döndürdüğü asıl hata açıklamasını göster
            # (ör. "model requires more system memory than is available")
            try:
                detay = e.read().decode("utf-8", errors="replace")
            except Exception:
                detay = ""
            print(f"{r.get('vuln_id')}: Ollama hata döndürdü -> HTTP {e.code} | {detay}")
            hatali += 1
            continue
        except Exception as e:
            print(f"{r.get('vuln_id')}: Ollama'ya ulaşılamadı -> {e}")
            hatali += 1
            continue
        sure = time.time() - baslangic
        sureler.append(sure)

        try:
            sonuc = json.loads(ham)
            skor = float(sonuc["risk_score"])
            gerekce = sonuc.get("reason", "")
            basarili += 1
            try:
                if abs(skor - float(r.get("cvss_score"))) < 0.05:
                    cvss_ile_ayni += 1
            except (TypeError, ValueError):
                pass
            print(f"{r.get('vuln_id')} | CVSS {r.get('cvss_score')} -> LLM {skor} "
                  f"| {sure:.1f} sn | {gerekce}")
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            hatali += 1
            # Ham yanıtın tamamı: kesilmiş mi, yoksa başka bir sorun mu, görülsün
            print(f"{r.get('vuln_id')} | GEÇERSİZ JSON | {sure:.1f} sn | "
                  f"{len(ham)} karakter | ham yanıt: {ham}")

    print("\n--- Özet ---")
    print(f"Model: {args.model} | Prompt dili: {args.dil}")
    print(f"Başarılı: {basarili} / {len(rows)}, hatalı: {hatali}")
    if basarili:
        print(f"LLM skoru CVSS ile aynı olan kayıt: {cvss_ile_ayni} / {basarili}")
    if sureler:
        print(f"Kayıt başına ortalama süre: {sum(sureler) / len(sureler):.1f} sn")
        print(f"36 kayıt için tahmini süre: {sum(sureler) / len(sureler) * 36 / 60:.1f} dk")


if __name__ == "__main__":
    main()