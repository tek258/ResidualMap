# Kontroller Devredeyken Tarama ve Doğrulama Çıktıları (S5-K2)

**Tarih:** 18–19 Kasım 2026  
**Klasör:** `inventory/raw/after_controls/`  
**Amaç:** WAF engelleme modu, Suricata IDS, iki katmanlı Docker ağ segmentasyonu ve Keycloak IAM kontrolleri açıkken uygulamanın durumunu belgelemek. S6 sprintinde oluşturulacak `inventory/after_controls.csv` tablosunun ve artık risk hesaplarının kanıt tabanını oluşturur.

---

## 1. Test Ortamı ve Sürüm Bilgileri

| Bileşen | Belirlenen Sürüm / Kimlik | Notlar |
|---|---|---|
| **Hedef Uygulama** | `bkimminich/juice-shop:v20.2.0` | Çok platformlu manifest dizin digest'i: `sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`; yerel platform imaj katman digest'i (`ImageID`): `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`. İki değer de aynı imaja karşılık gelir. |
| **WAF** | `owasp/modsecurity-crs:4.30.0-nginx-202610180210` | ModSecurity v3 + OWASP CRS 4.30.0 |
| **WAF Modu** | `MODSEC_RULE_ENGINE: "On"` | Engelleme modu aktif; Inbound eşik: 5, Outbound eşik: 4, PL1 |
| **Sanal Yamalar & İstisnalar** | `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`, `REQUEST-900-VIRTUAL-PATCHES-JUICESHOP.conf` | I-1..I-4 yanlış pozitif istisnaları, SY-1 sanal yaması (kural 10100) |
| **IDS (Suricata)** | `jasonish/suricata:8.0.8` | ET Open (53.508 kural) + local.rules; `eth0` ve `eth1` dinleniyor |
| **Ağ Segmentasyonu** | `frontend` (172.30.1.0/24) ve `backend` (172.30.2.0/24, `internal: true`) | Juice Shop yalnızca backend'de, dış çıkışı yok |
| **IAM** | Keycloak 26.0 (`quay.io/keycloak/keycloak:26.0`) + oauth2-proxy v7.7.1 | `/ftp` ve `/metrics` yollarını koruyor |
| **ZAP Scanner** | `ghcr.io/zaproxy/zaproxy:2.17.0` | ZAP 2.17.0 (Baseline pasif tarayıcı, sürüm sabitlendi) |
| **Trivy Scanner** | `aquasec/trivy:0.75.0` | Trivy v0.75.0 (sürüm sabitlendi). `trivy --version`: `Vulnerability DB: Version: ⟪DOLDUR⟫, UpdatedAt: ⟪DOLDUR⟫`. Tarama zamanı (`trivy.json` → `CreatedAt`): 2026-11-18 22:35 |

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
  ghcr.io/zaproxy/zaproxy:2.17.0 zap-baseline.py \
  -t http://host.docker.internal:8080 \
  -J zap_baseline.json
```

### 2.3 Trivy Konteyner İmaj Taraması
```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v residualmap-trivy-cache:/root/.cache/ \
  -v "${PWD}/inventory/raw/after_controls:/out" \
  aquasec/trivy:0.75.0 image \
  --scanners vuln \
  --format json \
  -o /out/trivy.json \
  bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b
```
> Çıktıyı `>` ile değil `-o` ile yazın: PowerShell `>` dosyayı BOM'lu (ya da UTF-16) kaydeder ve JSON okuyucular hata verir. DB sürümü: `docker run --rm -v residualmap-trivy-cache:/root/.cache/ aquasec/trivy:0.75.0 --version`.

### 2.4 WAF, IAM ve Kullanıcı Akışları Testleri
```bash
# WAF saldırı ve kontrol yükleri testi (13 istek):
bash defense/test-waf.sh > inventory/raw/after_controls/test-waf.log 2>&1

# Kapsamlı kullanıcı akışları ve istisna sınır testleri (70 istek):
python3 defense/test-juice-flows.py > inventory/raw/after_controls/test-juice-flows.log 2>&1

# IAM (Keycloak + oauth2-proxy) erişim kontrolü testi (17 kontrol):
python3 defense/test-iam.py > inventory/raw/after_controls/test-iam.log 2>&1

# Testler sonrası zafiyet çözüm durumunun kaydedilmesi (0 çözülen kanıtı):
curl -s http://localhost:8080/api/Challenges/ > inventory/raw/after_controls/challenges.json
```

---

## 3. ZAP Baseline Önce / Sonra Karşılaştırması

ZAP baseline taraması pasif bir taramadır; enjeksiyon payload'ı göndermez, sunucu başlıklarını ve HTTP yanıt yapılandırmalarını inceler.

| Metrik | Referans (`inventory/raw/`) | Kontroller Sonrası (`after_controls/`) | Değişim |
|---|---|---|---|
| **Tarama Tarihi** | 08.10.2026 | 18.11.2026 | +41 gün |
| **Hedef Adres** | `http://host.docker.internal:8080` | `http://host.docker.internal:8080` | Aynı (WAF) |
| **Toplam Bulgu Türü (Alert)** | **12** | **11** | **-1 (Kaybolan)** |
| **Toplam Örnek Sayısı (Instances)** | **49** | **44** | **-5** |

### 3.1 Kaybolan Bulgular (1 adet)
* **`Server Leaks Version Information via "Server" HTTP Response Header Field` (Plugin ID: 10036, Risk: Low)**
  * **Envanter Karşılığı:** **V019**
  * **Açıklama:** Referans taramadaki (`inventory/raw/zap_baseline.json`) 5 örneğin kanıtı `Server: nginx/1.31.6` idi; yani sürüm bilgisini sızdıran doğrudan Juice Shop (Express) değil, WAF katmanındaki Nginx ters vekilinin kendi başlığıydı. Kontroller sonrası taramada (`after_controls/zap_baseline.json`) 10036 hiç yok: **5 örnek → 0**. Başlık, WAF imajının (`owasp/modsecurity-crs:4.30.0-nginx-202610180210`) varsayılan `server_tokens off` ayarıyla gizleniyor; `SERVER_TOKENS` ve `SERVER_HEADER` değişkenleri compose dosyasına taramalardan sonra açıkça eklendi. Eşlemede `waf: engeller`, `dayanak: test` (kanıt: ZAP önce/sonra).

### 3.2 Değişmeyen / Kalan Bulgular (11 adet)
Aşağıdaki başlık ve yapılandırma eksiklikleri WAF ters vekilinde özel olarak eklenmediği için taramada varlığını sürdürmektedir:
1. `Content Security Policy (CSP) Header Not Set` (Plugin ID: 10038, Risk: Medium) → **V017** (`waf: etkisiz`, `dayanak: test`)
2. `Cross-Domain Misconfiguration` (Plugin ID: 10098, Risk: Medium) → **V018** (`waf: etkisiz`, `dayanak: test`)
3. `Cross-Origin-Embedder-Policy Header Missing or Invalid` (Plugin ID: 90004, Risk: Low) → **V021** (`waf: etkisiz`, `dayanak: test`)
4. `Cross-Origin-Opener-Policy Header Missing or Invalid` (Plugin ID: 90004, Risk: Low) → **V021** (`waf: etkisiz`, `dayanak: test`)
5. `Dangerous JS Functions` (Plugin ID: 10110, Risk: Low) → **V020** (`waf: etkisiz`, `dayanak: test`)
6. `Deprecated Feature Policy Header Set` (Plugin ID: 10063, Risk: Low)
7. `Timestamp Disclosure - Unix` (Plugin ID: 10096, Risk: Low)
8. `Modern Web Application` (Plugin ID: 10109, Risk: Info)
9. `Non-Storable Content` (Plugin ID: 10049, Risk: Info)
10. `Storable and Cacheable Content` (Plugin ID: 10049, Risk: Info)
11. `Storable but Non-Cacheable Content` (Plugin ID: 10049, Risk: Info)

> **V016:** Kontroller sonrası ZAP taramasının URL listesinde iç yığın izi yolları (`layer.js:95:5`, `fileServer.js:52:13`) görünüyor; bu, hata sayfalarının WAF'tan geçtiğine dolaylı bir işaret. Hata yanıtının kendisi kaydedilmediği için dayanak `gerekce` (`waf: etkisiz`).

### 3.3 Yeni Çıkan Bulgular
* **Yok (0 adet).** WAF veya Nginx yapılandırması yeni bir pasif tarama uyarısına sebep olmamıştır.

---

## 4. Trivy İmaj Taraması Karşılaştırması

* **Referans Tarama:** 08.10.2026, Trivy v0.75.0 → **175 zafiyet**
* **Kontroller Sonrası Tarama:** 18.11.2026, Trivy v0.75.0 (DB sürümü Bölüm 1'de) → **200 zafiyet**
* **Neden Arttı?**
  * **Aynı imaj:** İki raporda da `Metadata.ImageID` = `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e` ve `RepoDigests` aynı. (Compose'daki `sha256:8739101a…` çok platformlu manifest dizininin digest'i; `73c53fbf…` yerel platform imajı.)
  * **Fark:** `(VulnerabilityID, paket, sürüm)` üçlüsüyle karşılaştırıldığında 25 bulgu eklenmiş, hiçbiri çıkmamış. Eklenen 25 bulgunun **hepsi `brace-expansion`** paketine ait.
  * **Sonuç:** Paketler değişmediği için artış Trivy zafiyet veritabanının güncellenmesinden kaynaklanıyor.
  * Savunma kontrolleri (WAF, Suricata, segmentasyon, IAM) imajdaki paketleri değiştirmez; hiçbir yama uygulanmadı. Kütüphane zafiyetleri (V022–V036) aynen duruyor (`yama: uygulanmadi`, `waf: etkisiz`).

---

## 5. Web ve Yetkilendirme Zafiyetleri Doğrulama Özeti

| Vuln ID | Zafiyet Adı | İlgili Test / Kanıt | Beklenen önceki durum (S1 envanteri) → Sonra (bu klasördeki loglar) | Sonuç ve Dayanak |
|---|---|---|---|---|
| **V001** | Login SQL Injection | `test-waf.sh: "V001 SQLi (email alanı)"` | 200 OK (Admin token) → **403 Forbidden** | CRS 942100 tek kuralla, tam eşikte (5 puan) yakalıyor (`waf: azaltir`, `dayanak: test`) |
| **V002** | Arama SQL Injection | `test-waf.sh: "SQLi"` | 500 Error → **403 Forbidden** | CRS 942100 tek kuralla, tam eşikte (5 puan) yakalıyor (`waf: azaltir`, `dayanak: test`) |
| **V003** | Sipariş Takibi Reflected XSS & NoSQLi | `test-waf.sh: "V003 XSS (yol içinde iframe)"` ve `"V003 yolu NoSQLi (' \|\| true \|\| ')"` | 200 OK → **403 Forbidden** | 403 alıyor: sanal yama SY-1 (kural 10100) engelliyor; CRS'nin (941xxx) de tetiklenip tetiklenmediği audit log'da ayrıca doğrulanacak (`sanal_yama: engeller`, `dayanak: test`) |
| **V004** | Arama DOM XSS | İstemci tarafı DOM manipülasyonu (`#/search`) | DOM XSS tarayıcıda çalışır → **WAF inceleyemez** | DOM XSS tarayıcıda çalıştığı ve yük sunucuya HTTP isteği olarak gitmediği için WAF engellemez (`waf: etkisiz`, `dayanak: gerekce`) |
| **V005** | API-only Stored XSS | `test-waf.sh: "V005 XSS (description alanı)"` | 404 (İstek iletildi) → **403 Forbidden** | CRS 941xxx kuralları JSON gövdesinde XSS tespit ediyor (`waf: engeller`, 25 puan, `dayanak: test`) |
| **V009** | /ftp Gizli Doküman İfşası | `test-iam.py`: `keycloaka_gider("/ftp/")` & `giris_akisi` | 200 OK (Doğrudan indirme) → **302 Redirect / 403 Forbidden** | Keycloak + oauth2-proxy kimliksiz erişimi 302 ile Keycloak'a yönlendiriyor, rolsüz misafire 403 veriyor (`iam: engeller`, `dayanak: test`) |
| **V010** | XXE Dosya Okuma | `docs/iam-segmentasyon-notu.md` Bölüm 3.3 (ağ çıkış testi) | İstek geçer → **Bant dışı veri çıkışı engellendi** | `test-juice-flows.py` XXE'yi test etmez. Backend ağı `internal: true` olduğundan harici sunucuya veri sızdırılamaz (`segmentasyon: azaltir`, `dayanak: gerekce`) |
| **V016** | Ayrıntılı Hata Mesajı | `zap_baseline.json` (`layer.js:95:5`, `fileServer.js:52:13`) & `docs/waf-engelleme-notu.md` | Hata sızıyor → **Hata sızıyor (Değişmedi)** | JSON ve hata yanıtları WAF tarafından denetlenmez; ZAP'ın URL listesinde yığın izi yolları görünüyor, hata yanıtının kendisi kaydedilmedi (`waf: etkisiz`, `dayanak: gerekce`) |
| **V019** | Sunucu Sürüm Sızıntısı | `zap_baseline.json` (Plugin ID: 10036) | 5 örnek (`Server: nginx/1.31.6`) → **0 örnek (Kayboldu)** | WAF imajının varsayılan `server_tokens off` ayarıyla başlık gizleniyor; kanıt ZAP önce/sonra karşılaştırması (`waf: engeller`, `dayanak: test`) |

### 5.1 Challenges Durumu (`challenges.json`)
`challenges.json` dosyası, tüm test betikleri (`test-waf.sh`, `test-juice-flows.py`, `test-iam.py`) çalıştırıldıktan hemen sonra kaydedilmiştir. Toplam 116 challenge arasından çözülen sayısı **0**'dır (`solved: false`). Test yüklerinin çoğu challenge çözüm yükü olmadığı için bu sayı tek başına "kontroller saldırıları durdurdu" anlamına gelmez. Anlamlı olan V001: `test-waf.sh`'taki `' OR 1=1--` girişi engellenmeseydi "Login Admin" challenge'ı çözülürdü; 403 aldığı için çözülmedi.

---

## 6. Bu Klasördeki Dosyalar

* `README.md`: Bu dokümantasyon, tarama karşılaştırma raporu ve tekrarlanabilirlik rehberi.
* `zap_baseline.json`: Kontroller devredeyken WAF üzerinden alınan pasif ZAP tarama çıktısı (11 alert türü, 44 örnek).
* `trivy.json`: Pinned Juice Shop v20.2.0 imajının güncel Trivy veritabanıyla taranmış JSON çıktısı (200 zafiyet).
* `challenges.json`: Testler sonrasında Juice Shop `/api/Challenges/` uç noktasından alınan durum (116 challenge, 0 çözülen).
* `test-waf.log`: `defense/test-waf.sh` çalıştırma çıktısı (13 istek, 0 hata).
* `test-juice-flows.log`: `defense/test-juice-flows.py` çalıştırma çıktısı (70 istek, 0 hata).
* `test-iam.log`: `defense/test-iam.py` çalıştırma çıktısı (17 kontrol, 0 hata).
