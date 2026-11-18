# Kontroller Devredeyken Tarama ve Doğrulama Çıktıları (S5-K2)

**Tarih:** 18–19 Kasım 2026  
**Klasör:** `inventory/raw/after_controls/`  
**Amaç:** WAF engelleme modu, Suricata IDS, iki katmanlı Docker ağ segmentasyonu ve Keycloak IAM kontrolleri açıkken uygulamanın durumunu belgelemek. S6 sprintinde oluşturulacak `inventory/after_controls.csv` tablosunun ve artık risk hesaplarının kanıt tabanını oluşturur.

---

## 1. Test Ortamı ve Sürüm Bilgileri

| Bileşen | Belirlenen Sürüm / Kimlik | Notlar |
|---|---|---|
| **Hedef Uygulama** | `bkimminich/juice-shop:v20.2.0` | Digest: `sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b` |
| **WAF** | `owasp/modsecurity-crs:4.30.0-nginx-202610180210` | ModSecurity v3 + OWASP CRS 4.30.0 |
| **WAF Modu** | `MODSEC_RULE_ENGINE: "On"` | Engelleme modu aktif; Inbound eşik: 5, Outbound eşik: 4, PL1 |
| **Sanal Yamalar & İstisnalar** | `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`, `REQUEST-900-VIRTUAL-PATCHES-JUICESHOP.conf` | I-1..I-3 yanlış pozitif istisnaları, SY-1 sanal yaması (kural 10100) |
| **IDS (Suricata)** | `jasonish/suricata:8.0.8` | ET Open (53.508 kural) + local.rules; `eth0` ve `eth1` dinleniyor |
| **Ağ Segmentasyonu** | `frontend` (172.30.1.0/24) ve `backend` (172.30.2.0/24, `internal: true`) | Juice Shop yalnızca backend'de, dış çıkışı yok |
| **IAM** | Keycloak 26.0 (`quay.io/keycloak/keycloak:26.0`) + oauth2-proxy v7.7.1 | `/ftp` ve `/metrics` yollarını koruyor |
| **ZAP Scanner** | `ghcr.io/zaproxy/zaproxy:stable` | ZAP 2.17.0 (Baseline pasif tarayıcı) |
| **Trivy Scanner** | `aquasec/trivy:latest` | Trivy v0.75.0, DB Schema v2 (18.11.2026 güncel veritabanı) |

---

## 2. Taramaları ve Testleri Tekrarlama Adımları (Reproducibility Guide)

Taramaları aynı koşullarda yeniden üretmek için repo kökünden aşağıdaki adımları sırasıyla çalıştırın:

### 2.1 Savunma Ortamını Ayağa Kaldırma
```bash
cd defense
docker compose down
docker compose up -d
```
Giriş noktası: `http://localhost:8080` (WAF üzerinden). Juice Shop'a doğrudan erişim (port 3000) kapalıdır.

### 2.2 ZAP Baseline Taraması (WAF Üzerinden)
> **Kritik:** Tarama doğrudan Juice Shop'a değil, WAF'ın yayınlandığı `http://host.docker.internal:8080` adresine yapılmalıdır.
```bash
# Repo kök dizininde (ResidualMap):
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "${PWD}/inventory/raw/after_controls:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://host.docker.internal:8080 \
  -J zap_baseline.json
```

### 2.3 Trivy Konteyner İmaj Taraması
```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v residualmap-trivy-cache:/root/.cache/ \
  aquasec/trivy:latest image \
  --scanners vuln \
  --format json \
  bkimminich/juice-shop:v20.2.0 > inventory/raw/after_controls/trivy.json
```

### 2.4 WAF ve Normal Kullanıcı Akışları Testleri
```bash
# WAF saldırı ve kontrol yükleri testi:
bash defense/test-waf.sh > inventory/raw/after_controls/test-waf.log 2>&1

# Kapsamlı kullanıcı akışları ve istisna sınır testleri:
python3 defense/test-juice-flows.py > inventory/raw/after_controls/test-juice-flows.log 2>&1

# IAM (Keycloak + oauth2-proxy) erişim kontrolü testi:
python3 defense/test-iam.py > inventory/raw/after_controls/test-iam.log 2>&1
```

---

## 3. ZAP Baseline Önce / Sonra Karşılaştırması

ZAP baseline taraması pasif bir taramadır; enjeksiyon payload'ı göndermez, sunucu başlıklarını ve HTTP yanıt yapılandırmalarını inceler.

| Metrik | Referans (`inventory/raw/`) | Kontroller Sonrası (`after_controls/`) | Değişim |
|---|---|---|---|
| **Tarama Tarihi** | 08.10.2026 | 18.11.2026 | +41 gün |
| **Hedef Adres** | `http://host.docker.internal:8080` | `http://host.docker.internal:8080` | Aynı (WAF) |
| **Toplam Bulgu Türü (Alert)** | **12** | **11** | **-1 (Kaybolan)** |
| **Toplam Örnek Sayısı (Instances)** | **45** | **40** | **-5** |

### 3.1 Kaybolan Bulgular (1 adet)
* **`Server Leaks Version Information via "Server" HTTP Response Header Field` (Plugin ID: 10036, Risk: Low)**
  * **Envanter Karşılığı:** **V019**
  * **Açıklama:** Kontroller öncesinde Juice Shop doğrudan `Server: Express` başlığı döndürüyordu. WAF (Nginx ters vekili) araya girdiğinde arka uç sunucu sürüm başlığını gizlediği için bulgu tamamen kaybolmuştur (`dayanak: test`, `waf: engeller`).

### 3.2 Değişmeyen / Kalan Bulgular (11 adet)
Aşağıdaki başlık ve yapılandırma eksiklikleri WAF ters vekilinde özel olarak eklenmediği için taramada varlığını sürdürmektedir:
1. `Content Security Policy (CSP) Header Not Set` (Plugin ID: 10038, Risk: Medium) → **V017** (`waf: etkisiz`)
2. `Cross-Domain Misconfiguration` (Plugin ID: 10098, Risk: Medium) → **V018** (`waf: etkisiz`)
3. `Cross-Origin-Embedder-Policy Header Missing or Invalid` (Plugin ID: 90004, Risk: Low) → **V021** (`waf: etkisiz`)
4. `Cross-Origin-Opener-Policy Header Missing or Invalid` (Plugin ID: 90004, Risk: Low) → **V021** (`waf: etkisiz`)
5. `Dangerous JS Functions` (Plugin ID: 10110, Risk: Low) → **V020** (`waf: etkisiz`)
6. `Deprecated Feature Policy Header Set` (Plugin ID: 10063, Risk: Low)
7. `Timestamp Disclosure - Unix` (Plugin ID: 10096, Risk: Low)
8. `Modern Web Application` (Plugin ID: 10109, Risk: Info)
9. `Non-Storable Content` (Plugin ID: 10049, Risk: Info)
10. `Storable and Cacheable Content` (Plugin ID: 10049, Risk: Info)
11. `Storable but Non-Cacheable Content` (Plugin ID: 10049, Risk: Info)

### 3.3 Yeni Çıkan Bulgular
* **Yok (0 adet).** WAF veya Nginx yapılandırması yeni bir pasif tarama uyarısına sebep olmamıştır.

---

## 4. Trivy İmaj Taraması Karşılaştırması

* **Referans Tarama:** 08.10.2026, Trivy v0.75.0 → **175 zafiyet**
* **Kontroller Sonrası Tarama:** 18.11.2026, Trivy v0.75.0 (güncel DB) → **200 zafiyet**
* **Neden Arttı?**
  * İmaj digest'i (`sha256:8739101ade2...`) her iki taramada da birebir aynıdır; imaj katmanları veya paketler değiştirilmemiştir.
  * Artışın tek sebebi, **Trivy güvenlik açığı veritabanının (Vulnerability DB) güncellenmesidir**. Ekim ve Kasım 2026 arasında upstream NVD ve GitHub Advisory veritabanlarına eklenen yeni CVE kayıtları (özellikle `brace-expansion` vb. alt bağımlılıklar) nedeniyle tespit edilen toplam zafiyet sayısı 175'ten 200'e çıkmıştır.
  * **Önemli Sonuç:** Savunma kontrolleri (WAF, Suricata, Ağ Segmentasyonu) konteyner imajının paketlerini güncellemez (yama uygulamaz). Dolayısıyla kütüphane zafiyetleri (V022–V036) imaj seviyesinde aynen mevcuttur (`yama: engeller`, `waf: etkisiz`).

---

## 5. Web ve Yetkilendirme Zafiyetleri Doğrulama Özeti

| Vuln ID | Zafiyet Adı | İlgili Test / Dosya | Durum (Önce / Sonra) | Sonuç ve Kanıt |
|---|---|---|---|---|
| **V001** | Login SQL Injection | `test-waf.sh:35` | 200 OK (Admin token) → **403 Forbidden** | CRS 942100 tek kuralla tam eşikte (5 puan) yakalıyor (`waf: azaltir`) |
| **V002** | Arama SQL Injection | `test-waf.sh:28` | 500 Error → **403 Forbidden** | CRS 942100 tek kuralla tam eşikte (5 puan) yakalıyor (`waf: azaltir`) |
| **V003** | Sipariş Takibi Reflected XSS | `test-waf.sh:38-40` | 200 OK → **403 Forbidden** | Sanal yama SY-1 (kural 10100) regex doğrulamasıyla engelliyor (`sanal_yama: engeller`) |
| **V005** | API-only Stored XSS | `test-waf.sh:44` | 404 (İstek iletildi) → **403 Forbidden** | CRS 941xxx kuralları JSON gövdesinde XSS tespit ediyor (`waf: engeller`, 25 puan) |
| **V009** | /ftp Gizli Doküman İfşası | `test-iam.py:10-12` | 200 OK (Doğrudan indirme) → **302 Redirect / 403 Forbidden** | Keycloak + oauth2-proxy kimliksiz erişimi engelliyor, misafire 403 veriyor (`iam: engeller`) |
| **V010** | XXE Dosya Okuma | `test-juice-flows.py` & segmentasyon | İstek geçer → **Bant dışı veri çıkışı engellendi** | Backend ağı `internal: true` olduğundan harici sunucuya veri sızdırılamaz (`segmentasyon: azaltir`) |
| **V016** | Ayrıntılı Hata Mesajı | `docs/waf-engelleme-notu.md` | Hata sızıyor → **Hata sızıyor (Değişmedi)** | JSON yanıtlar WAF tarafından denetlenmediğinden WAF etkisizdir (`waf: etkisiz`) |
| **V019** | Sunucu Sürüm Sızıntısı | `zap_baseline.json` | 5 örnek (Express sızıntısı) → **0 örnek (Kayboldu)** | WAF ters vekili Server başlığını kaldırdı (`waf: engeller`) |

---

## 6. Bu Klasördeki Dosyalar

* `README.md`: Bu dokümantasyon ve tarama karşılaştırma raporu.
* `zap_baseline.json`: Kontroller devredeyken WAF üzerinden alınan pasif ZAP tarama çıktısı (11 alert türü).
* `trivy.json`: Pinned Juice Shop v20.2.0 imajının güncel Trivy veritabanıyla taranmış JSON çıktısı (200 zafiyet).
* `challenges.json`: Kontroller açıkken Juice Shop `/api/Challenges/` uç noktasından alınan güncel durum.
* `test-waf.log`: `defense/test-waf.sh` çalıştırma çıktısı (13 istek, 0 hata).
* `test-juice-flows.log`: `defense/test-juice-flows.py` çalıştırma çıktısı (70 istek, 0 hata).
* `test-iam.log`: `defense/test-iam.py` çalıştırma çıktısı (13 kontrol, 0 hata).
