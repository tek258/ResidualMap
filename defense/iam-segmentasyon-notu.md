# Ağ segmentasyonu ve IAM notu (S4-K5)

**Tarih:** 18.11.2026
**Kapsam:** `defense/docker-compose.yml`
**Sonuç:** Tek `lab` ağı, `frontend` ve `backend` olarak ikiye ayrıldı. Juice Shop yalnızca dışarıya çıkışı olmayan `backend` ağında. Host'tan da `frontend` ağından da doğrudan erişilemiyor; tek giriş noktası WAF (`localhost:8080`). Bütün imajlar sürüme sabitlendi. Segmentasyondan sonra `test-waf.sh` ve `test-juice-flows.py` beklenmeyen sonuç vermedi. Suricata artık WAF'ın iki bacağını da dinliyor: bu turdaki saldırı alarmlarının hepsi istemci bacağında, Juice Shop bacağında alarm yok. IAM (Keycloak) kurulmadı (Bölüm 5).

---

## 1. Yapılan değişiklikler

| Dosya | Değişiklik |
|---|---|
| `defense/docker-compose.yml` | `lab` ağı kaldırıldı; `frontend` (172.30.1.0/24) ve `backend` (172.30.2.0/24, `internal: true`) ağları eklendi. |
| `defense/docker-compose.yml` | Juice Shop yalnızca `backend`'e, WAF iki ağa bağlandı. WAF'ın IP'leri sabit (172.30.1.10 / 172.30.2.10); Suricata kayıtlarında hangi bacağın hangisi olduğu her kurulumda aynı kalıyor. |
| `defense/docker-compose.yml` | Juice Shop `bkimminich/juice-shop` (latest) → `bkimminich/juice-shop:v20.2.0` (digest `sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`). |
| `defense/docker-compose.yml` | Suricata `jasonish/suricata:latest` → `jasonish/suricata:8.0.8` (lab'da çalışan sürüm, `suricata -V`). |
| `defense/docker-compose.yml` | Suricata iki arayüzü de dinliyor: `-i eth0 -i eth1`. |
| `defense/test-waf.sh` | V003 satırı envanterdeki kayıtla eşleştirildi: envanterde V003 sipariş takibindeki **reflected XSS**. XSS satırı eklendi; aynı uç noktadaki NoSQL enjeksiyonu satırı ayrı etiketle korundu. |
| `app/config.py` | Uygulamanın Trivy taraması da `bkimminich/juice-shop:v20.2.0`'ı tarıyor (önceden etiketsiz `latest`). |

## 2. Ağ yapısı

```
istemci ──8080──> [frontend] waf-nginx [backend] ──3000──> juice-shop
                   eth0 172.30.1.10     eth1 172.30.2.10    172.30.2.2
                          └──── lab-suricata (iki arayüzü de dinler) ────┘
```

| Ağ | Bağlı container'lar | Dışarıya çıkış | Host'a açık port |
|---|---|---|---|
| `frontend` | waf-nginx | Var | 8080 |
| `backend` | waf-nginx, juice-shop | **Yok** (`internal: true`) | Yok |

**Neden "db" ağı yok:** Planda frontend/backend/db ayrımı vardı. Juice Shop ayrı bir veritabanı servisi kullanmıyor; veriyi container içindeki gömülü SQLite ve bellek içi bir veritabanında tutuyor. Ayrılacak bir veritabanı container'ı olmadığı için üçüncü ağ bu lab'da karşılıksız. Gerçek bir dağıtımda veritabanı ayrı bir servis olur ve yalnızca uygulamanın erişebildiği üçüncü bir ağa konur.

**Devreye alma notu:** Ağ tanımları değiştiği için `docker compose up -d --force-recreate` yetmez; önce `docker compose down` gerekir. `down` yalnızca compose dosyasında tanımlı ağları kaldırır. Dosya önceden değiştirildiyse eski `defense_lab` ağı boşta kalır, `docker network rm defense_lab` ile silinmeli (lab'da yapıldı; ağa bağlı container yoktu).

## 3. Doğrulama (18.11.2026, Windows + Docker Desktop, PowerShell)

### 3.1 Juice Shop host'tan erişilemiyor

| Komut | Sonuç |
|---|---|
| `curl.exe -s -o NUL -w "%{http_code}" -m 5 http://localhost:3000` | `000` (bağlantı yok) |
| `docker port juice-shop` | Boş (yayınlanan port yok) |

### 3.2 Juice Shop `frontend` ağından erişilemiyor

`frontend` ağına bağlı geçici bir container'dan (`curlimages/curl`):

| Hedef | Sonuç |
|---|---|
| `http://juice-shop:3000` (ad ile) | Çıkış kodu 28 (zaman aşımı) |
| `http://172.30.2.2:3000` (IP ile) | Çıkış kodu 28 (zaman aşımı) |

IP ile deneme önemli: ad çözülemese bile Docker ağlar arası trafiği güvenlik duvarı kurallarıyla engelliyor.

### 3.3 Juice Shop'tan dışarıya çıkış yok

| Kaynak → hedef | Sonuç |
|---|---|
| juice-shop → `https://example.com` (ad) | `EAI_AGAIN` (dış ad çözülemiyor) |
| juice-shop → `http://1.1.1.1` (IP) | `ENETUNREACH` (dışarıya ağ yolu yok) |
| waf-nginx → `http://1.1.1.1` (karşılaştırma) | `301` (WAF dışarıya çıkabiliyor) |

Kısıtlama `backend` ağından geliyor: WAF `frontend` üzerinden dışarı çıkabiliyor, yalnızca `backend`'de olan Juice Shop çıkamıyor.

### 3.4 WAF testleri

| Betik | Sonuç |
|---|---|
| `test-waf.sh` (segmentasyon sonrası, 12 satırlık sürüm) | 12 istek, 0 beklenmeyen sonuç |
| `test-juice-flows.py` | 70 istek (62 normal + 8 sınır testi), 0 beklenmeyen sonuç |

Segmentasyon WAF'ın davranışını değiştirmedi. Sepet, ödeme, dosya yükleme, socket.io ve sipariş takibi (SY-1 dahil) çalışıyor; istisnaların sınır testleri hâlâ 403 alıyor.

### 3.5 Suricata iki bacağı da dinliyor

`docker exec lab-suricata ip -4 -br addr`:

| Arayüz | Ağ | IP | Bacak |
|---|---|---|---|
| `eth0` | frontend | 172.30.1.10 | istemci ↔ WAF |
| `eth1` | backend | 172.30.2.10 | WAF ↔ Juice Shop |

Suricata başlangıç logunda hata yok. `HOME_NET` (`[172.16.0.0/12,192.168.0.0/16,10.0.0.0/8]`) yeni alt ağları kapsıyor, değişiklik gerekmedi.

`test-juice-flows.py` ve `test-waf.sh` sonrasında `eve.json`'daki son 2000 kaydın arayüze göre dağılımı:

| Olay türü | eth0 (istemci) | eth1 (Juice Shop) |
|---|---|---|
| http | 249 | 131 |
| flow | 213 | 131 |
| fileinfo | 71 | 0 |
| websocket | 26 | 0 |
| anomaly | 4 | 0 |
| **alert** | **4** | **0** |

**Yorum:**
- `eth1`'de HTTP ve bağlantı kayıtları var: Suricata Juice Shop bacağını da görüyor.
- Saldırı alarmlarının hepsi istemci bacağında, Juice Shop bacağında hiç alarm yok. WAF'ın 403 verdiği istekler uygulamaya hiç iletilmedi; bu artık ağ seviyesinde de görülüyor.
- İki bacak arasındaki HTTP sayısı farkının bir kısmı WAF'ın engellediği isteklerden geliyor. Fark tamamen bunlardan oluşmuyor (ör. `fileinfo` kayıtları yalnızca istemci bacağında), bu yüzden bu sayı "engellenen istek sayısı" olarak kullanılmamalı. Engellenen isteklerin sayısı için ModSecurity audit log'u esas alınmalı.
- Not: Bu tabloda istemci bacağındaki alarm sayısı 4. `test-waf.sh`'taki saldırı satırlarının hepsi Suricata alarmı üretmiyor; hangi kuralların tetiklendiği ve neden hepsinin tetiklenmediği S5'te ayrıca incelenmeli.

## 4. Segmentasyonun envantere etkisi

Envanterde (`inventory_v1.0.csv`, 36 kayıt) sunucunun kendisinin dışarıya istek attığı bir zafiyet (ör. CWE-918 SSRF) yok. Bu yüzden segmentasyon hiçbir kaydı doğrudan engellemiyor. Etkileri:

| Kayıt | Etki | Gerekçe |
|---|---|---|
| V010 (XXE) | Azaltır | Envanterdeki hali ("XXE Data Access") sunucudaki dosyayı okuyup yanıtta döndürüyor; dışarı çıkış gerektirmiyor ve etkilenmiyor. Ama XXE'nin veriyi saldırganın sunucusuna gönderen bant dışı türleri artık çalışmaz. |
| Admin yetkisi veren kayıtlar (V001, V008, V015, V030 vb.) | Sonrasını sınırlar | Zafiyet sömürülse bile uygulama dışarıya veri gönderemez ve dışarıdan araç indiremez. Zafiyetin kendisini değil, ele geçirme sonrasını etkiler; eşleme tablosuna değil rapora girer. |
| Bütün web kayıtları | Doğrudan etki yok | Saldırı trafiği zaten WAF üzerinden geliyor. Segmentasyonun asıl katkısı, WAF'ı atlayarak Juice Shop'a doğrudan ulaşma yolunu ağ seviyesinde kapatması (S3'e kadar bu yol yalnızca port yayınlanmadığı için kullanılamıyordu). |

K2'ye iletilecek: `control_mapping.csv`'de V010 için `segmentasyon / azaltir / gerekce` satırı.

## 5. IAM (Keycloak)

**Durum: Kurulmadı.**

**Gerekçe:**
- Juice Shop OIDC ya da SAML desteklemiyor; kendi kullanıcı tablosu ve JWT'siyle çalışıyor. Keycloak'u devreye sokmanın tek yolu, uygulamanın önüne ayrı bir kimlik doğrulama proxy'si (ör. oauth2-proxy) koymak.
- Böyle bir proxy uygulamanın kendi yollarını koruyamaz: ön yüz bu yollara kendi JWT'siyle erişiyor, proxy araya girince uygulama bozulur. Proxy yalnızca uygulamanın kullanmadığı operasyon yollarını (ör. `/metrics`) koruyabilir.
- Envanterdeki kimlik doğrulama ve yetkilendirme zafiyetleri (V001, V006, V007, V008, V011, V015, V022, V030) uygulamanın kendi mantığında. Bunların çözümü uygulamanın yetkilendirmesini düzeltmek; önündeki bir IAM katmanı bu zafiyetlerin hiçbirinin durumunu değiştirmez.
- Proxy için WAF'ın nginx yapılandırmasının değiştirilmesi gerekiyor. Bu, S3'te ve bu sprintte doğrulanan 12 + 70 testlik düzeni bozma riski taşıyor; kazancı ise artık risk sonucunu etkilemeyen bir demo.

**Sonuç:** Takvim (teslim 30.11.2026) ve kazanç göz önüne alınarak IAM kapsam dışı bırakıldı. `control_mapping.csv`'deki IAM satırları `kurulmadi` olarak işaretlenmeli (K2).

**Gerçek bir dağıtımda:** Uygulama Keycloak'u kimlik sağlayıcı olarak doğrudan kullanır (OIDC), yönetici uç noktaları rol tabanlı yetkilendirmeyle korunur.

## 6. Kapsam dışı ve sınırlılıklar

- Segmentasyon container ağları seviyesinde. Host üzerindeki Docker yöneticisi (root) her ağa erişebilir.
- WAF iki ağa da bağlı; WAF ele geçirilirse `backend`'e erişim sağlanır. Bu, ters proxy mimarisinin doğal sonucu.
- Juice Shop container'ı ile Docker'ın kendi DNS'i arasındaki iletişim açık (container adları çözülebiliyor). Dış ad çözümlemesi kapalı.

## 7. Açık iş

- [ ] `test-waf.sh` V003 XSS satırı eklendi; güncel sürüm (13 istek) lab'da çalıştırılıp sonucu bu nota yazılmalı.
