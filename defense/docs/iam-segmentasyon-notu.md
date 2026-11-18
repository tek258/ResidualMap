# Ağ segmentasyonu ve IAM notu (S4-K5)

**Tarih:** 18.11.2026
**Kapsam:** `defense/docker-compose.yml`, `defense/nginx/default.conf.template`, `defense/iam/realm-lab.json`, `defense/modsecurity/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` (I-4)

**Sonuç:**
- **Segmentasyon:** Tek `lab` ağı, `frontend` ve `backend` olarak ikiye ayrıldı. Juice Shop yalnızca dışarıya çıkışı olmayan `backend` ağında; host'tan da `frontend` ağından da doğrudan erişilemiyor. Tek giriş noktası WAF (`localhost:8080`). Bütün imajlar sürüme sabitlendi.
- **IAM:** Keycloak (kimlik sağlayıcı) ve oauth2-proxy kuruldu. `/ftp` (V009, gizli belge dizini) ve `/metrics` artık yalnızca Keycloak'ta `ops` rolüne sahip kullanıcılara açık. Girişsiz istekler Keycloak'a yönlendiriliyor, rolü olmayan kullanıcı 403 alıyor. Altı atlatma denemesinin hiçbiri içeriğe ulaşamadı.
- **WAF ile uyum:** Keycloak'un geri dönüşü CRS 934110 ile engelleniyordu (YP-4); dar bir istisnayla (I-4) giderildi.
- **Testler:** `test-iam.py` 17/0, `test-waf.sh` 13/0, `test-juice-flows.py` 70/0 (IAM ve I-4 eklendikten sonra; mevcut düzen bozulmadı).

---

## 1. Yapılan değişiklikler

| Dosya | Değişiklik |
|---|---|
| `defense/docker-compose.yml` | `lab` ağı kaldırıldı; `frontend` (172.30.1.0/24) ve `backend` (172.30.2.0/24, `internal: true`) ağları eklendi. |
| `defense/docker-compose.yml` | Juice Shop yalnızca `backend`'e, WAF iki ağa bağlandı. WAF'ın IP'leri sabit (172.30.1.10 / 172.30.2.10); Suricata kayıtlarında hangi bacağın hangisi olduğu her kurulumda aynı kalıyor. |
| `defense/docker-compose.yml` | Juice Shop `bkimminich/juice-shop` (latest) → `bkimminich/juice-shop:v20.2.0` (digest `sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`). |
| `defense/docker-compose.yml` | Suricata `jasonish/suricata:latest` → `jasonish/suricata:8.0.8`; iki arayüzü de dinliyor (`-i eth0 -i eth1`). |
| `defense/docker-compose.yml` | **Yeni servisler:** `keycloak` (`quay.io/keycloak/keycloak:26.0`, host'ta 8081) ve `oauth2-proxy` (`quay.io/oauth2-proxy/oauth2-proxy:v7.7.1`, host'a açık değil). İkisi de `frontend` ağında. |
| `defense/nginx/default.conf.template` | **Yeni.** CRS imajının kendi şablonunun kopyası; HTTP sunucusuna yalnızca `/oauth2/`, `/oauth2/auth` ve `/ftp`, `/metrics` blokları eklendi. |
| `defense/iam/realm-lab.json` | **Yeni.** `lab` realm'i, `juice-ops` client'ı, `ops` rolü, `personel` (ops) ve `misafir` (rolsüz) kullanıcıları. Keycloak açılışta bu dosyayı içe aktarıyor. |
| `defense/modsecurity/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` | **I-4 (ID 10040)** eklendi: OIDC geri dönüşündeki `iss` parametresi (Bölüm 5.4). |
| `defense/test-iam.py` | **Yeni.** 17 kontrol: korumasız yollar, korumalı yollar, atlatma denemeleri, iç adres, I-4 sınırı ve gerçek giriş akışı (yalnızca standart kütüphane). |
| `defense/test-waf.sh` | V003 satırı envanterle eşleştirildi (envanterde V003 = reflected XSS); XSS satırı eklendi, NoSQL satırı ayrı etiketle korundu. |
| `app/config.py` | Uygulamanın Trivy taraması da `bkimminich/juice-shop:v20.2.0`'ı tarıyor. |

## 2. Ağ yapısı

```
                      ┌──────────── frontend (172.30.1.0/24) ────────────┐
istemci ──8080──> waf-nginx ──/ftp, /metrics──> oauth2-proxy ──> keycloak <──8081── istemci (giriş sayfası)
                      │ (eth0 172.30.1.10)        (yalnızca "izin var mı?")
                      │
                      └── backend (172.30.2.0/24, internal) ──3000──> juice-shop (172.30.2.2)
                          (eth1 172.30.2.10)

lab-suricata: WAF'ın iki arayüzünü de dinler (eth0 + eth1)
```

| Ağ | Bağlı container'lar | Dışarıya çıkış | Host'a açık port |
|---|---|---|---|
| `frontend` | waf-nginx, oauth2-proxy, keycloak | Var | 8080 (WAF), 8081 (Keycloak) |
| `backend` | waf-nginx, juice-shop | **Yok** (`internal: true`) | Yok |

**Neden "db" ağı yok:** Planda frontend/backend/db ayrımı vardı. Juice Shop ayrı bir veritabanı servisi kullanmıyor; veriyi container içindeki gömülü SQLite ve bellek içi bir veritabanında tutuyor. Ayrılacak bir veritabanı container'ı olmadığı için üçüncü ağ bu lab'da karşılıksız. Gerçek bir dağıtımda veritabanı ayrı bir servis olur ve yalnızca uygulamanın erişebildiği üçüncü bir ağa konur.

**Devreye alma notu:** Ağ tanımları değiştiği için `docker compose up -d --force-recreate` yetmez; önce `docker compose down` gerekir. `down` yalnızca compose dosyasında tanımlı ağları kaldırır. Dosya önceden değiştirildiyse eski `defense_lab` ağı boşta kalır, `docker network rm defense_lab` ile silinmeli (lab'da yapıldı; ağa bağlı container yoktu). Keycloak realm'i yalnızca ilk açılışta içe aktarır; `realm-lab.json` değişirse `docker compose up -d --force-recreate keycloak oauth2-proxy` gerekir.

## 3. Segmentasyon doğrulaması (18.11.2026, Windows + Docker Desktop, PowerShell)

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

IP ile deneme önemli: ad çözülemese bile Docker ağlar arası trafiği güvenlik duvarı kurallarıyla engelliyor. Aynı sonuç `frontend`'deki oauth2-proxy ve Keycloak için de geçerli: ikisi de Juice Shop'a doğrudan ulaşamaz.

### 3.3 Juice Shop'tan dışarıya çıkış yok

| Kaynak → hedef | Sonuç |
|---|---|
| juice-shop → `https://example.com` (ad) | `EAI_AGAIN` (dış ad çözülemiyor) |
| juice-shop → `http://1.1.1.1` (IP) | `ENETUNREACH` (dışarıya ağ yolu yok) |
| waf-nginx → `http://1.1.1.1` (karşılaştırma) | `301` (WAF dışarıya çıkabiliyor) |

### 3.4 Suricata iki bacağı da dinliyor

`docker exec lab-suricata ip -4 -br addr`:

| Arayüz | Ağ | IP | Bacak |
|---|---|---|---|
| `eth0` | frontend | 172.30.1.10 | istemci ↔ WAF (ve WAF ↔ oauth2-proxy) |
| `eth1` | backend | 172.30.2.10 | WAF ↔ Juice Shop |

**Dikkat:** Bu eşleşme 18.11.2026 sabahki kuruluma ait. WAF yeniden oluşturulduğunda (ör. I-4 sonrası) Docker ağları farklı sırayla bağlayabiliyor ve `eth0`/`eth1` yer değiştirebiliyor; aynı gün bu oldu. Bacağı belirlemek için arayüz adı değil **IP adresi** kullanılmalı (172.30.1.x istemci bacağı, 172.30.2.x Juice Shop bacağı). Log panosu bu yüzden bacağı IP'den belirliyor (`docs/siem-kurulum.md`).

| Zaman | `eth0` | `eth1` |
|---|---|---|
| 18.11.2026 sabah (segmentasyon sonrası) | 172.30.1.10 (frontend) | 172.30.2.10 (backend) |
| 18.11.2026 akşam (I-4 için WAF yeniden oluşturulduktan sonra) | **172.30.2.10 (backend)** | **172.30.1.10 (frontend)** |

Kaynak: `docker exec lab-suricata ip -4 -br addr`.

Suricata başlangıç logunda hata yok. `HOME_NET` (`[172.16.0.0/12,192.168.0.0/16,10.0.0.0/8]`) yeni alt ağları kapsıyor.

`test-juice-flows.py` ve `test-waf.sh` sonrasında (IAM eklenmeden önce) `eve.json`'daki son 2000 kaydın arayüze göre dağılımı:

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
- İki bacak arasındaki HTTP sayısı farkı yalnızca engellenen isteklerden oluşmuyor (ör. `fileinfo` kayıtları yalnızca istemci bacağında); bu fark "engellenen istek sayısı" olarak kullanılmamalı. Engellenen istekler için ModSecurity audit log'u esas alınmalı.
- `test-waf.sh`'taki saldırı satırlarının hepsi Suricata alarmı üretmiyor (4 alarm); hangi kuralların tetiklendiği S5'te ayrıca incelenmeli.

## 4. Segmentasyonun envantere etkisi

Envanterde (`inventory_v1.0.csv`, 36 kayıt) sunucunun kendisinin dışarıya istek attığı bir zafiyet (ör. CWE-918 SSRF) yok. Bu yüzden segmentasyon hiçbir kaydı doğrudan engellemiyor.

| Kayıt | Etki | Gerekçe |
|---|---|---|
| V010 (XXE) | Azaltır | Envanterdeki hali ("XXE Data Access") sunucudaki dosyayı okuyup yanıtta döndürüyor; dışarı çıkış gerektirmiyor ve etkilenmiyor. Ama XXE'nin veriyi saldırganın sunucusuna gönderen bant dışı türleri artık çalışmaz. |
| Admin yetkisi veren kayıtlar (V001, V008, V015, V030 vb.) | Sonrasını sınırlar | Zafiyet sömürülse bile uygulama dışarıya veri gönderemez ve dışarıdan araç indiremez. Zafiyetin kendisini değil ele geçirme sonrasını etkiler; eşleme tablosuna değil rapora girer. |
| Bütün web kayıtları | Doğrudan etki yok | Saldırı trafiği zaten WAF üzerinden geliyor. Segmentasyonun asıl katkısı, WAF'ı atlayarak Juice Shop'a doğrudan ulaşma yolunu ağ seviyesinde kapatması. |

## 5. IAM (Keycloak + oauth2-proxy)

### 5.1 Neden bu mimari

Juice Shop OIDC ya da SAML desteklemiyor; kendi kullanıcı tablosu ve JWT'siyle çalışıyor. Keycloak bu yüzden uygulamanın **içine** değil **önüne** konuldu:

- **Keycloak:** kimlik sağlayıcı. Kullanıcılar, şifreler ve roller burada.
- **oauth2-proxy:** WAF'ın her korumalı istekte sorduğu kapı. Trafiği kendisi taşımıyor (`--upstream=static://202`), yalnızca "bu isteğin geçerli bir Keycloak oturumu ve `ops` rolü var mı?" sorusuna cevap veriyor.
- **nginx (`auth_request`):** korumalı yollarda isteği Juice Shop'a iletmeden önce oauth2-proxy'ye soruyor. WAF önde kalıyor: `/ftp` istekleri önce ModSecurity'den, sonra kimlik kontrolünden geçiyor.

**Neden yalnızca `/ftp` ve `/metrics`:** Juice Shop'un ön yüzü kendi API'sine kendi JWT'siyle erişiyor; bu yolların önüne ikinci bir giriş koymak uygulamayı bozar. `/ftp` (belge dizini) ve `/metrics` (Prometheus metrikleri) ön yüzün normal kullanımında gerekmeyen, yalnızca personelin erişmesi gereken yollar. `/ftp` envanterdeki **V009**'un (CWE-548, dizin listeleme ile gizli belgeye erişim) giriş noktası.

### 5.2 Akış

| İstek | Sonuç |
|---|---|
| Girişsiz `/ftp/` | 302 → Keycloak giriş sayfası (`localhost:8081`) |
| `personel` (ops rolü) ile giriş | Geri dönüşte oturum açılıyor → `/ftp/` dosya listesi (200) |
| `misafir` (rolsüz) ile giriş | Keycloak girişi kabul ediyor; oauth2-proxy geri dönüşte rolü kontrol edip oturum açmadan 403 veriyor |
| Korumasız yollar (`/`, `/rest/...`, `/api/...`) | Değişmedi, kimlik sorulmuyor |

oauth2-proxy logu (18.11.2026):
```
personel@lab.local [AuthSuccess] Authenticated via OAuth2: Session{... PreferredUsername:personel ... groups:[role:ops]}
misafir@lab.local  [AuthFailure] Invalid authentication via OAuth2: unauthorized
```

### 5.3 `test-iam.py` sonuçları (17 kontrol, 0 beklenmeyen)

| Bölüm | Kontrol | Sonuç |
|---|---|---|
| Korumasız yollar | ana sayfa, ürün arama | 200, 200 |
| Korumalı yollar (girişsiz) | `/ftp/`, `/ftp`, `/ftp/legal.md`, `/metrics` | 4 × 302 → Keycloak |
| Atlatma denemeleri | `/FTP/`, `/Ftp/legal.md`, `//ftp/`, `/%66tp/`, `/./ftp/`, `/METRICS` | 6 × 302 → Keycloak |
| İç adres | `/oauth2/auth` dışarıdan | 404 |
| I-4 sınırı | `iss` = bulut metadata adresi; iki `iss` parametresi | 403, 403 (WAF, 934110) |
| Giriş akışı | `personel` → `/ftp/` | 200 |
| Giriş akışı | `misafir` → `/ftp/` | 403 (oauth2-proxy, rol yok) |

**Atlatmaya karşı:** Express yolları büyük/küçük harf ayırmadığı için nginx bloğu büyük/küçük harf duyarsız (`~*`). nginx, eşleştirmeden önce `%xx` kodlamasını çözüyor, `//` ve `./` ifadelerini normalize ediyor. Altı varyasyonun hepsi Keycloak'a yönlendirildi.

**Kapalı-güvenli (fail-closed):** oauth2-proxy kapalıysa korumalı yollar 500 döner, içerik açılmaz. Diğer yollar etkilenmez (nginx oauth2-proxy adresini açılışta değil istek anında çözüyor).

### 5.4 WAF ile uyum: YP-4 ve I-4 istisnası

**Sorun:** Keycloak'tan dönüşte tarayıcı `/oauth2/callback?state=...&session_state=...&iss=http://localhost:8081/realms/lab&code=...` adresine gidiyor. `iss` parametresi OIDC standardının (RFC 9207) bir parçası ve Keycloak'un kendi adresini taşıyor. CRS **934110** ("Possible SSRF: ... URL in Parameter") parametredeki `http://localhost`'u SSRF girişimi sanıyor; puan 5 = eşik, her giriş 403 ile bitiyordu. Audit log:

```
934110  Possible Server Side Request Forgery (SSRF) Attack: Cloud provider metadata URL in Parameter
        [Matched Data: http://localhost found within ARGS:iss: http://localhost:8081/realms/lab]
949110  Inbound Anomaly Score Exceeded (Total Score: 5)
```

**İstisna (I-4, ID 10040):** S3-K5'teki I-1..I-3 ile aynı ilke: kural kapatılmadı, yalnızca dört koşul birlikte sağlandığında `iss` parametresi 934110'dan çıkarılıyor:
1. yol tam olarak `/oauth2/callback`,
2. parametre `iss`,
3. istekte **tam olarak bir** `iss` parametresi var (`iss=bizimki&iss=başka` ile atlatılamaz),
4. değer **tam olarak** `http://localhost:8081/realms/lab`.

Aynı isteğin `code`, `state` ve `session_state` parametreleri bütün kurallarla denetlenmeye devam ediyor.

**Sınır testleri** (audit log ile doğrulandı):

| İstek | Sonuç | Kurallar |
|---|---|---|
| `/oauth2/callback?iss=http://169.254.169.254/latest/meta-data` | 403 | 931100, 934110 |
| `/oauth2/callback?iss=<bizimki>&iss=http://localhost:9999/` | 403 | 934110 |
| `misafir` geri dönüşü (gerçek giriş) | 403 | Kural yok: 403 oauth2-proxy'den (rol). Audit log yalnızca yanıt kodu yüzünden kaydetti. |
| `personel` geri dönüşü (gerçek giriş) | Geçti | Audit log'da kayıt yok |

**Bakım:** Keycloak adresi (`KC_HOSTNAME`) ya da realm adı değişirse I-4'teki değer de değişmeli; aksi halde girişler yine 403 alır.

### 5.5 Kurulum sırasında çıkan iki sorun

| Sorun | Neden | Çözüm |
|---|---|---|
| `invalid_scope: openid email profile` | JSON'dan içe aktarılan client'a varsayılan kapsamlar otomatik atanmıyor | `realm-lab.json`'da client'a `defaultClientScopes` eklendi |
| `invalid_scope: ... groups` | `--allowed-group` kullanınca oauth2-proxy Keycloak'tan `groups` kapsamı istiyor; realm'de böyle bir kapsam yok | Grup yerine realm rolü (`ops`) ve `--allowed-role=ops` |

### 5.6 Envantere etkisi

| Kayıt | Kontrol | Etki | Dayanak | Kanıt |
|---|---|---|---|---|
| V009 (`/ftp` gizli belge) | IAM | Engeller (girişsiz ve rolsüz erişim) | test | `test-iam.py`: girişsiz `/ftp/` → 302, 6 atlatma denemesi → 302, `misafir` → 403 |

Diğer kimlik doğrulama ve yetkilendirme kayıtları (V001, V006, V007, V008, V011, V015, V022, V030) uygulamanın kendi mantığında. IAM katmanı bu kayıtların durumunu değiştirmiyor; çözümleri uygulamanın yetkilendirmesini düzeltmek.

**V009 için sınırlılık:** IAM `/ftp`'ye *yetkisiz* erişimi engelliyor. `ops` rolündeki bir personel dizini hâlâ görebiliyor; dizinde gizli belge bulunması (asıl sorun) uygulama tarafında çözülmeli.

### 5.7 Gizli bilgiler

Keycloak yönetici şifresi, kullanıcı şifreleri, client secret ve çerez anahtarı compose dosyasında ve `realm-lab.json`'da açık yazılı. Bu yalnızca izole lab için bilinçli bir tercih: temiz bir makinede tek komutla aynı ortam kurulabiliyor (S8). Gerçek bir dağıtımda bu değerler bir gizli bilgi yöneticisinden (Docker secrets, Vault vb.) gelir ve repoya girmez.

## 6. Kapsam dışı ve sınırlılıklar

- Segmentasyon container ağları seviyesinde. Host üzerindeki Docker yöneticisi (root) her ağa erişebilir.
- WAF iki ağa da bağlı; WAF ele geçirilirse `backend`'e erişim sağlanır. Bu, ters proxy mimarisinin doğal sonucu.
- Keycloak'un giriş sayfası (8081) WAF'ın arkasında değil, doğrudan host'a açık. Keycloak'un kendi kaba kuvvet koruması açık (`bruteForceProtected`, 5 hatalı deneme).
- Keycloak geliştirme modunda (`start-dev`) ve HTTP üzerinde çalışıyor; veriler container içinde, container silinince realm dosyadan yeniden yükleniyor.
- Juice Shop container'ı Docker'ın kendi DNS'ine erişebiliyor (container adları çözülüyor); dış ad çözümlemesi kapalı.

## 7. Açık iş

- [x] `test-waf.sh` (13 satırlık sürüm, V003 XSS dahil) 13/0 ve `test-juice-flows.py` 70/0, IAM ve I-4 eklendikten sonra (18.11.2026).
- [x] Tarayıcı ekran görüntüleri (`docs/img/`):
  - `iam-1-keycloak-giris.png`: girişsiz `/ftp/` → `localhost:8081/realms/lab/...` (Keycloak giriş sayfası)
  - `iam-2-personel-ftp.png`: `personel` ile `localhost:8080/ftp/` dosya listesi. Listede `incident-support.kdbx` (şifre kasası), `coupons_2013.md.bak`, `package.json.bak` gibi dosyalar var; IAM öncesinde bu liste kimlik doğrulamasız herkese açıktı (V009).
  - `iam-3-misafir-403.png`: `misafir` ile girişten sonra `localhost:8080/oauth2/callback` → 403 Forbidden (oauth2-proxy v7.7.1)
