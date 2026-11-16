# Model v1 Değerlendirme Raporu (`phi3:mini`)

## 1. Amaç ve Yöntem
Bu çalışmada, OWASP Juice Shop hedefli 36 zafiyet kaydı (`inventory/inventory_v1.0.csv`) üzerinde yerel LLM (`phi3:mini`, Ollama API) kullanarak CVSS-only baseline yönteminden daha bağlamsal bir risk önceliklendirmesi yapılması hedeflenmiştir.

- **Betik:** `ai/model_v1_local_llm.py`
- **Çıktı Dosyası:** `ai/results_v1_llm.csv`
- **Referans Etiketler:** `ai/expert_labels.csv` (K2 Uzman Etiketleme Ölçütü)
- **Hata Yönetimi:** JSON ayrıştırma ve sunucu (`HTTP 500`) hataları `try/except` ve yeniden deneme (retry) mekanizması ile yönetilmiş, başarısız kayıtlar `ai/model_v1_execution.log` dosyasına kaydedilmiştir.

---

## 2. Nicel Metrikler

| Metrik | Sonuç | Açıklama |
|---|---|---|
| **İşlenen Kayıt Oranı** | **35 / 36 (%97.2)** | `V014` kaydı Ollama `500 Internal Server Error` nedeniyle 3 deneme sonunda atlandı. |
| **CVSS Baseline Top-10 Örtüşme Oranı** | **%90.0 (9/10)** | Modelin sayısal risk skorları büyük ölçüde girdi CVSS puanlarıyla örtüştü. |
| **K2 Uzman Etiketleri Kategori Uyum Oranı** | **%37.14 (13/35)** | Uzman Etiketleme Ölçütü sınıflarıyla (`Kritik`, `Yüksek`, `Orta`, `Düşük`) birebir eşleşme oranı. |

---

## 3. Nitel Bulgular ve Hata Analizi

1. **"Yüksek" Sınıfına Yığılma (Sınıf Dengesizliği):**
   - İşlenen 35 kaydın **30 tanesi `Yüksek`** olarak etiketlenmiştir. K2 ile eşleşen 13 kaydın tamamı (`V002`, `V009`, `V010`, `V015`, `V024`, `V026`, `V028`–`V034`) bu gruptadır.
   - Model, CVSS puanı `3.1` (`V018`, `V021`) ve `4.2` (`V017`, `V020`) olan düşük etkili başlık/yapılandırma bulgularını dahi `Yüksek` sınıfına atadığı için K2'nin `Orta` ve `Düşük` sınıflarında eşleşme sağlanamamıştır.
2. **CVSS Çapalama Etkisi (Anchoring Bias):**
   - `phi3:mini` modeli `risk_score_llm` üretirken CVSS skorunu doğrudan kopyalama eğilimi göstermiştir (örn. `V001` için `9.8`, `V003` için `6.1`). Bu durum Top-10 örtüşme oranının `%90.0` seviyesinde kalmasına yol açmıştır.
3. **Bağımlılık (Trivy) ve Uygulama Kanıtı Ayrımı:**
   - Uzman ölçütünde bağımlılık taraması (Trivy) bulguları kod yolunun erişilebilirliği doğrulanmadığı için `Yüksek` seviyesinde tutulurken (`V022`, `V023`, `V025`, `V027`), model yüksek CVSS değerlerinden etkilenerek bu kayıtlara `Kritik` etiketi vermiştir. Buna karşılık doğrudan uygulama kanıtı bulunan `V001` ve `V008` kayıtlarını `Yüksek` olarak sınıflandırmıştır.
4. **Alan Karışıklığı (`V035`):**
   - `V035` kaydında model `risk_score_llm` alanına CVSS (`9.8`) yerine EPSS değerini (`0.00718`) yazarak kaydı `Düşük` olarak sınıflandırmıştır.

---

## 4. Model v2 İçin İyileştirme Önerileri
- **Few-Shot Prompting:** Uzman Etiketleme Ölçütü'nden her sınıf (`Kritik`, `Yüksek`, `Orta`, `Düşük`) için 1'er adet örnek kayıt ve gerekçe prompt içine eklenerek "Yüksek" sınıfına yığılma azaltılmalıdır.
- **Sayısal Skor Kalibrasyonu:** Prompt içinde CVSS skorunun doğrudan kopyalanmaması, EPSS ve erişilebilirlik koşullarına göre ağırlıklandırılması açıkça belirtilmelidir.
- **Daha Büyük Yerel Model Testi:** `phi3:mini` (3.8B) yerine `llama3.1:8b` veya `qwen2.5:7b` gibi talimat takibi daha güçlü modellerle kıyaslama yapılmalıdır.