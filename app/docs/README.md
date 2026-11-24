# ResidualMap lab uygulaması

Lab hedefinin seçilmesinden saldırı grafiğine ve savunma testine kadar olan akışı tek bir arayüzde birleştiren Streamlit uygulaması. Makine önerir ve doğrular, kullanıcı onaylar.

| Adım | Ne yapar |
|---|---|
| Özet | Projenin sonucunu tek ekranda gösterir: zafiyet ve yol sayısı, artık risk düşüşü, kesilen yollar, 16 saatlik önlem planı ve önce/sonra grafiği. "Demoyu başlat" 1. adıma geçer |
| 1. Hedef | İzin listesindeki lab hedefini seçer, çalıştırma başlatır (ya da örnek veriyle başlatır) |
| 2. Tarama | ZAP baseline, Trivy ve Juice Shop challenge listesini canlı toplar ya da repodaki ham dosyaları yükler |
| 3. Bulgular | Ham çıktıları ayrıştırır, dondurulmuş envanterle karşılaştırır, grafiğe girecek bulguları seçtirir. Envanterde olmayan yeni kayıtların grafikteki yerini ekip kuralı, MITRE CWE etkisi ve AI önerisiyle önerir; kullanıcı onaylar (docs/yeni-zafiyet-baglama.md) |
| 4. Grafik | Kenarları, saldırı yollarını ve etkileşimli grafiği üretir; CVSS ve AI (model v2) sıralamasını yan yana gösterir. "Model ne düşündü?" paneli bir kayıt için modele giden kanıtı, kararı, gerekçeyi ve tam prompt'u gösterir; kayıt canlı skorlanabilir |
| 5. Savunma testi | Lab'ın WAF doğrulama testini çalıştırır; sonuçlar savunma panosunda (Grafana) da görünür |
| 6. Önlem seçimi | Aday önlemlerden (yama, kod düzeltmesi, yapılandırma) efor bütçesine göre en iyi bileşimi önerir; seçilen önlemlerle kalan riski ve değişen yolları gösterir. Ekibin sonuç dosyalarıyla çalışır, çalıştırma ve Docker gerektirmez. "Planı AI ile açıkla" seçilen planı yerel modelle Türkçe anlatır; model hesap yapmaz, yazdığı sayılar denetlenir |

## Değişmez kurallar

1. **Hedef serbest yazılamaz.** Uygulama yalnızca `app/config.py`'deki izin listesindeki yerel lab hedeflerini tarar. Adres girme alanı yoktur. Listeye yerel olmayan bir adres eklenirse uygulama açılmaz.
2. **Rapor sonuçları dondurulmuş envanterden gelir** (`inventory/inventory_v1.0.csv`). Uygulamada yapılan seçimler raporun sayılarını değiştirmez.
3. **Ekibin scriptleri yeniden yazılmaz,** fonksiyon olarak çağrılır: `graph/` (kenar, yol, grafik), `ai/model_v2_local_llm.py`, `defense/test-waf.sh`.

## Kurulum

Gerekenler:

| | Zorunlu mu | Ne için |
|---|---|---|
| Python 3.11+ | Evet | Uygulama |
| Docker Desktop | Canlı tarama ve savunma testi için | Lab ortamı, ZAP, Trivy |
| Git for Windows (Git Bash) | Savunma testi için | `test-waf.sh` bash ile çalışır |
| Ollama + `qwen2.5:7b` | Hayır | Yeni bulguları AI ile skorlamak |

Repo kök dizininde:

```powershell
pip install -r requirements-app.txt
```

## Çalıştırma

### Örnek veriyle (Docker gerekmez)

```powershell
streamlit run app/main.py
```

1. **1. Hedef** → "Örnek veriyle başlat"
2. **3. Bulgular** → "Dondurulmuş envanteri uygula" → "Seçimi kaydet"
3. **4. Grafik** → "Grafiği oluştur"

Ekibin `inventory/raw/` altındaki ZAP, Trivy ve challenge dosyaları kullanılır. Grafik 36 zafiyet, 72 kenar ve 36 yolla, repodaki `graph/edges.json` / `graph/paths.json` ile aynı çıkar. AI skorları hazır sonuçtan (`ai/results_v2_llm.csv`) gelir.

### Lab ortamıyla (canlı tarama ve savunma testi)

Uygulamayı açıp yan menüdeki **"Ortamı başlat"** düğmesine basmak yeterli: Docker Desktop'ı, lab'ı (`docker compose --profile siem up -d`), savunma panosunu ve Ollama'yı sırayla başlatır, model yoksa indirir ve belleğe yükler. Docker Desktop'ın ve Ollama'nın kendisi önceden kurulu olmalı. Elle başlatmak için:

```powershell
cd defense
docker compose --profile siem up -d   # siem profili savunma panosunu da açar; istenmezse çıkarın
cd ..
streamlit run app/main.py
```

- **1. Hedef:** Docker ve Juice Shop konteyneri yeşil görünmeli → "Yeni çalıştırma başlat".
- **2. Tarama:** "Canlı topla". İlk çalıştırmada ZAP (~1.5 GB) ve Trivy imajları indirilir. ZAP taraması birkaç dakika sürer. ZAP baseline pasiftir: hedefe saldırı isteği göndermez.
- **3. ve 4. adım:** Örnek veriyle aynı.
- **5. Savunma testi:** "Saldırı testlerini çalıştır". 41 kontrol yapılır, beklenen sonuç 14 WAF engellemesi ve 0 beklenmeyen sonuçtur. Test en sonda hız sınırını denediği için ardından ~2 dakika giriş istekleri 429 alabilir.
- **6. Önlem seçimi:** Lab gerektirmez. Bütçe kaydırıcısı en iyi bileşimi bulur (bütün alt kümeler denenir, ~1 sn); seçim elle değiştirilebilir.
- **Savunma panosu:** Yan menüdeki "Savunma panosu (Grafana)" düğmesi panoyu yeni sekmede açar (`admin` / compose dosyasındaki lab şifresi).

### AI skoru (isteğe bağlı)

Dondurulmuş envanterdeki kayıtların skoru hazırdır. Yeni taramadan gelen kayıtlar "AI skoru yok" görünür. Bu kayıtları skorlamak için:

```powershell
ollama pull qwen2.5:7b
```

Ollama açıkken 4. adımdaki "N kaydı modelle skorla" düğmesi etkin olur. Kayıt başına ~3 sn sürer (GPU). Skorlama bitince grafik yeni skorlarla yeniden üretilir.

## Çıktılar

Her çalıştırma `runs/<tarih-saat>/` altında tutulur (gitignore'da):

```
runs/20261119-153012/
├── meta.json          adımlar, seçimler, test sonuçları
├── raw/               zap_baseline.json, trivy.json, challenges.json
├── inventory.csv      bu çalıştırmanın envanteri
├── ai_skorlari.csv    AI skorları ve kaynağı (hazır sonuç / model)
└── graph/             edges.json, paths.json, attack_graph.html
```

4. adımdaki "Hepsini indir (zip)" bunların hepsini tek dosyada indirir.

## Sorun giderme

| Belirti | Neden / çözüm |
|---|---|
| 1. adımda "Docker çalışmıyor" | Docker Desktop'ı başlatın, "Durumu yenile". Docker olmadan "Örnek veriyle başlat" kullanılabilir |
| "Savunma panosu kapalı" | `defense/` klasöründe `docker compose --profile siem up -d` |
| Savunma testi düğmesi pasif, "Git Bash bulunamadı" | Git for Windows kurun. WSL bash bilerek kullanılmaz |
| Canlı tarama sırasında yüksek bellek | ZAP (Java) ve ilk imaj indirmesi. Normaldir; Docker'ın toplam belleği `%USERPROFILE%\.wslconfig` içinde `memory=10GB` ile sınırlanabilir |
| Panoda WAF olayı yok | Tarama pasiftir, WAF'ın engelleyeceği istek göndermez. Olaylar 5. adımdaki savunma testinden sonra görünür; panoda zaman aralığını "Son 15 dakika" seçin |
| 3. adımda JSON hatası | `inventory/raw/` altındaki bir dosya bozuk olabilir (PowerShell `>` ile yazılan dosyalar UTF-16 olur). Dosyayı `-o` ya da `Out-File -Encoding utf8` ile yeniden üretin |
