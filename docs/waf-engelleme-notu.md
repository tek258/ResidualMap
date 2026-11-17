# WAF engelleme modu notu (H5-K6)

**Tarih:** 17.11.2026
**Kapsam:** `defense/docker-compose.yml` içindeki `waf` servisi (owasp/modsecurity-crs:nginx) ve arkasındaki Juice Shop
**Sonuç:** WAF tespit modundan (DetectionOnly) engelleme moduna (On) geçirildi. Normal kullanımda üç yanlış pozitif kaynağı bulundu. Üçü de dar kapsamlı istisnalarla giderildi. Saldırı örnekleri 403 alıyor, test edilen 62 normal istek ise sorunsuz geçiyor.

---

## 1. Yapılan değişiklikler

| Dosya | Değişiklik |
|---|---|
| `defense/docker-compose.yml` | `MODSEC_RULE_ENGINE: DetectionOnly` değeri `"On"` yapıldı. |
| `defense/docker-compose.yml` | `ALLOWED_METHODS: "GET HEAD POST OPTIONS"` açıkça yazıldı. Bu CRS'in zaten varsayılan değeri; davranış değişmedi, politika görünür hale geldi. |
| `defense/docker-compose.yml` | İstisna dosyası salt okunur bağlandı: `./modsecurity/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` → `/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` |
| `defense/modsecurity/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` | **Yeni.** Juice Shop istisnaları (kural ID 10010, 10011, 10012, 10020, 10030). |
| `defense/test-juice-flows.py` | **Yeni.** Normal kullanıcı akışlarını ve istisnaların sınırını test eden betik (yalnızca standart kütüphane). |

Diğer ayarlar değişmedi: PL1, blocking PL1, inbound eşiği 5, outbound eşiği 4, audit log JSON.

## 2. Devreye alma

```bash
cd defense
docker compose up -d --force-recreate waf suricata
./test-waf.sh                    # normal 200, saldırı 403
python3 test-juice-flows.py      # 0 beklenmeyen sonuç, çıkış kodu 0
```

`suricata` servisi `network_mode: "service:waf"` ile WAF'ın ağ arayüzünü paylaşıyor. WAF container'ı yeniden oluşturulduğunda Suricata'nın da yeniden oluşturulması gerekir; aksi halde Suricata eski ve artık var olmayan bir ağ arayüzünü dinlemeye devam eder. Komuttaki `suricata` bu yüzden var.

**Geri alma:** `MODSEC_RULE_ENGINE: DetectionOnly` yapıp aynı komutu çalıştırmak yeterli.

## 3. Test ortamı

Testlerin yapıldığı çalışma ortamı Docker Hub'a ve ghcr.io'ya erişemedi. Bu yüzden container yerine aynı bileşenlerle eşdeğer bir kurulum kullanıldı:

| Bileşen | Lab (compose) | Test edilen |
|---|---|---|
| CRS | `owasp/modsecurity-crs:nginx` → CRS **4.30.0** | CRS **4.30.0** (git tag) |
| ModSecurity | v3 (imajın içinden) | libmodsecurity 3.0.12 + ModSecurity-nginx 1.0.3 |
| nginx | nginx-unprivileged 1.30 | nginx 1.24 |
| Juice Shop | `bkimminich/juice-shop` (latest) | Juice Shop **v20.4.0** (GitHub sürüm paketi) |
| CRS ayarları | PL1 / blocking PL1 / 5 / 4, allowed_methods varsayılan | Aynı (crs-setup içinde 900200 dahil) |
| ModSecurity ayarları | İmaj varsayılanları | İmaj şablonu taklit edildi: istek ve yanıt gövdesi denetimi açık, JSON/XML gövde işlemcileri, gövde ayrıştırma hatasında 400 |

Kurallar ve uygulama sürümleri lab ile birebir aynı, yalnızca nginx sürümü farklı.

**Lab doğrulaması (17.11.2026, `s3k5/wafengelleme` dalı):** Compose ile devreye alındıktan sonra container'da `SecRuleEngine On` görüldü, istisna kuralları yüklendi ve nginx logunda hata yok. `test-waf.sh` normal trafikte 200, 4 saldırı örneğinde 403 döndü. `test-juice-flows.py` (ilk sürüm) sonucu: 68 istek, 0 beklenmeyen sonuç.

Ardından tarayıcıyla yapılan elle testte audit log'da YP-3 (socket.io POST, 920420) görüldü. Betik bu isteği kapsamıyordu. I-3 istisnası eklendi ve betiğe socket.io POST testi eklendi; güncel sonuç: 70 istek, 0 beklenmeyen sonuç.

## 4. `test-waf.sh` sonuçları

| İstek | DetectionOnly (önce) | On (sonra) | Tetiklenen kurallar (On) |
|---|---|---|---|
| ana sayfa | 200 | **200** | — |
| ürün listesi (`q=apple`) | 200 | **200** | — |
| SQLi (`' OR 1=1--`) | **500** | **403** | 942100 (libinjection SQLi) → skor 5 |
| XSS (`<script>…`) | 200 | **403** | 941100, 941110, 941160, 941390 → skor 20 |
| Path traversal | 200 | **403** | 930100, 930110, 930120, 932160 → skor 30 |
| Scanner UA (`sqlmap`) | 200 | **403** | 913100 → skor 5 |

Not: DetectionOnly modunda SQLi isteği Juice Shop'a ulaşıp **500** (SQL hatası) döndürüyor; uygulamanın bu açığı gerçekten var. Engelleme modunda istek uygulamaya hiç ulaşmıyor. `test-waf.sh` içindeki "DetectionOnly'de hepsi 200 döner" yorumu bu yüzden tam doğru değil.

## 5. Yanlış pozitif taraması

**Yöntem:** `test-juice-flows.py`, tarayıcının gönderdiği isteklerin aynısını (başlıklar, JSON gövdeler, `token` çerezi, `Authorization` başlığı) WAF üzerinden gönderir. Her sonuç audit log ile karşılaştırıldı.

**Kapsanan akışlar (62 normal istek):**
- **Vitrin ve arama:** ana sayfa, uygulama ayarları, dil listesi, socket.io (polling GET ve `text/plain` POST), ürün yorumları; 8 farklı arama (Türkçe karakter, parantez, tire ve boşluk içerenler dahil)
- **Kayıt ve giriş:** kayıt, giriş, `whoami`, yanlış şifreyle giriş (401 beklenir)
- **Sepet:** görüntüleme, ekleme, adet değiştirme (PUT), silme (DELETE), kupon (PUT)
- **Yorumlar:** yazma (PUT), düzenleme (PATCH), beğenme (POST)
- **Adres ve kart:** adres ekleme, düzenleme ve silme; kart ekleme ve silme; teslimat seçenekleri; cüzdan bakiyesi ve yükleme (PUT); ödeme; sipariş geçmişi; sipariş takibi
- **Destek:** captcha ile iletişim formu, PDF şikâyet dosyası yükleme (multipart)
- **Özel karakterli şifreler:** 6 farklı şifreyle kayıt ve giriş: `Ayşe'nin-Sifresi1`, `kedi&kopek=2026`, `P@ss w0rd; <3`, `Sifre"123"!`, `1q2w3e4r--`, `admin123#`
- **Profil:** şifre değiştirme

**Bulgular (istisnalardan önce):** Betikte 9 istek yanlışlıkla 403 aldı; tarayıcı testinde de socket.io POST istekleri engellendi. Hepsi üç kaynaktan geliyor:

| # | Kural | Etkilenen | Etki |
|---|---|---|---|
| YP-1 | **911100**: Method is not allowed by policy | Sepette adet değiştirme ve silme, kupon, yorum yazma ve düzenleme, adres düzenleme ve silme, kart silme, cüzdana para yükleme | Sepet, yorum, adres ve kart yönetimi tamamen bozuluyor. |
| YP-2 | **932260**: Direct Unix Command Execution | `GET /rest/user/whoami` | Ön yüz bu uç noktayı her sayfa yüklemesinde çağırıyor. Giriş yapmış her kullanıcı her sayfada 403 alıyor. |
| YP-3 | **920420**: Request content type is not allowed by policy | `POST /socket.io/?EIO=4&transport=polling…` (`Content-Type: text/plain`) | Tarayıcıda her sayfa açıldığında birkaç saniyede bir 403 oluşuyor; canlı bağlantı (bildirimler) kurulamıyor. Betik yalnızca GET gönderdiği için ilk turda yakalanmadı, tarayıcı testinde audit log'da görüldü. |

Arama, giriş, özel karakterli şifreler, dosya yükleme, iletişim formu ve ödeme yanlış pozitif üretmedi.

## 6. İstisnalar

İki ilke izlendi: hiçbir CRS kuralı tamamen kapatılmadı, ve her istisna belirli bir yol ile belirli bir metod veya değişkenle sınırlandı. Kurallar `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` içinde ve CRS'ten önce, faz 1'de çalışıyor.

### I-1: Uç nokta bazlı metod izni (YP-1) | ID 10010, 10011, 10012

- **Ne yapıyor:** Yalnızca aşağıdaki yollar için `tx.allowed_methods` değerine ilgili metodu ekliyor. Diğer bütün yollarda politika `GET HEAD POST OPTIONS` olarak kalıyor.
- **Liste nereden geldi:** Juice Shop v20.4.0 ön yüz kaynak kodu (`frontend/src/app/Services/*.service.ts`). Ön yüzün kullandığı her PUT, PATCH ve DELETE çağrısı listede; fazlası yok.

| Metod | Yol (regex, `REQUEST_FILENAME`) | Kullanan ekran |
|---|---|---|
| PUT | `/api/BasketItems/{id}` | Sepet adedi |
| PUT | `/api/Addresss/{id}` | Adres düzenleme |
| PUT | `/api/Hints/{id}` | Skor tablosu ipucu |
| PUT | `/api/Products/{id}` | Muhasebe: fiyat değiştirme |
| PUT | `/api/Quantitys/{id}` | Muhasebe: stok değiştirme |
| PUT | `/rest/basket/{id}/coupon/{kod}` | Kupon |
| PUT | `/rest/products/{id}/reviews` | Yorum yazma |
| PUT | `/rest/wallet/balance` | Cüzdana para yükleme |
| PUT | `/rest/order-history/{id}/delivery-status` | Muhasebe: teslim durumu |
| PUT | `/rest/continue-code(-findIt\|-fixIt)/apply/{kod}` | İlerleme geri yükleme |
| DELETE | `/api/BasketItems/{id}` | Sepetten silme |
| DELETE | `/api/Addresss/{id}` | Adres silme |
| DELETE | `/api/Cards/{id}` | Kart silme |
| DELETE | `/api/Feedbacks/{id}` | Yönetici: geri bildirim silme |
| DELETE | `/rest/passkey/credentials/{id}` | Passkey silme |
| PATCH | `/rest/products/reviews` | Yorum düzenleme |

- **Neden site geneli `ALLOWED_METHODS` değil:** `ALLOWED_METHODS="… PUT PATCH DELETE"` yazmak daha kolay olurdu. Ama o zaman `PUT /api/Users/1` gibi ön yüzün hiç kullanmadığı yollar da metod politikasından geçerdi. Uç nokta bazlı izinle bu istekler hâlâ 403 alıyor (bkz. Bölüm 7).
- **Kalan risk:** Muhasebe ve yönetici uç noktaları (`/api/Products`, `/api/Quantitys`, `/api/Feedbacks`, `delivery-status`) listede, çünkü ön yüz bunları gerçekten kullanıyor. Bu uç noktalara yetkisiz erişimi engellemek uygulamanın yetkilendirme işi; WAF'ın metod politikası bunun yerini tutmaz. Bu isteklerin gövdeleri ve parametreleri CRS'in diğer bütün kurallarıyla denetlenmeye devam ediyor.
- **Bakım:** Juice Shop güncellenip yeni bir PUT, PATCH veya DELETE uç noktası eklenirse, o uç nokta 911100 nedeniyle 403 alır. Audit log'da 911100 görülürse ilgili regex'e eklenmeli ve bu tablo güncellenmeli.

### I-2: `whoami` yolu (YP-2) | ID 10020

- **Ne yapıyor:** Yalnızca `REQUEST_FILENAME == /rest/user/whoami` olduğunda 932260 kuralının **yalnızca** `REQUEST_FILENAME` hedefini kaldırıyor (`ctl:ruleRemoveTargetById=932260;REQUEST_FILENAME`).
- **Neden:** 932260, `whoami` kelimesini bir Unix komutu olarak tanıyor. Burada eşleşen şey kullanıcı girdisi değil, uygulamanın sabit bir uç nokta adı.
- **Kalan risk:** Yok denecek kadar az. Aynı istekteki parametreler, başlıklar ve çerezler 932260 dahil bütün kurallarla denetleniyor. Başka bir yolda veya parametrede geçen `whoami` hâlâ engelleniyor.

### I-3: socket.io polling (YP-3) | ID 10030

- **Ne yapıyor:** Yalnızca `POST /socket.io/` isteklerinde izinli içerik türü listesini `|text/plain|` yapıyor. Bu yolda yalnızca `text/plain` kabul ediliyor; diğer bütün yollarda CRS'in içerik türü politikası (JSON, form, multipart, XML) aynen geçerli. Örneğin `/rest/user/login` adresine `text/plain` gönderilirse hâlâ 403 alıyor.
- **Neden:** Juice Shop'un ön yüzü socket.io (Engine.IO v4) kullanıyor. Polling modunda tarayıcı mesajları `Content-Type: text/plain;charset=UTF-8` ile POST ediyor. CRS 4'ün izinli içerik türleri arasında `text/plain` olmadığı için bu istekler sürekli 403 alıyordu.
- **Kalan risk ve WAF sınırlaması:** ModSecurity `text/plain` gövdeleri parametrelere ayırmıyor; CRS'in saldırı kuralları da çoğunlukla parametrelere bakıyor. Bu yüzden socket.io mesajlarının **içeriği WAF tarafından denetlenmiyor**. Testte `42["x","<script>…</script>"]` gövdesi 200 aldı. Bu açığı istisna yaratmıyor: istisna olmasaydı da 920420 içeriğe bakmadan her mesajı engelliyordu. Bağlantı WebSocket'e yükseltildiğinde ise ModSecurity mesajları hiç göremiyor. Socket.io kanalının güvenliği uygulama tarafındaki doğrulamaya bağlı. Juice Shop sunucusu istemciden yalnızca dört socket olayı alıyor (`notification received`, `verifyLocalXssChallenge`, `verifySvgInjectionChallenge`, `verifyCloseNotificationsChallenge`; kaynak: `lib/startup/registerWebsocketEvents.ts`). Bunların hepsi bildirim ve challenge takibiyle ilgili; kullanıcı, sepet ya da sipariş verisine dokunan bir olay yok.
- **Kalan denetim:** URL, query string (`EIO`, `transport`, `t`, `sid`), başlıklar ve çerezler CRS'in bütün kurallarıyla denetlenmeye devam ediyor.

## 7. İstisnaların sınır testleri

`test-juice-flows.py` en sonda istisnaların fazla geniş olmadığını da kontrol ediyor (bu istekler 403 almalı):

| İstek | Sonuç | Kural |
|---|---|---|
| `PUT /api/Users/1` (listede yok) | 403 | 911100 |
| `DELETE /api/Products/1` (PUT listede, DELETE yok) | 403 | 911100 |
| `PATCH /api/BasketItems/1` | 403 | 911100 |
| `PUT /api/BasketItems/1/../../Users/1` (regex atlatma denemesi) | 403 | 911100, 930100, 930110 |
| `TRACE /` | 405 | nginx, ModSecurity'ye ulaşmadan reddediyor |
| `GET /rest/user/whoami?cb=;cat /etc/passwd` | 403 | 930120, 932160 |
| `GET /rest/products/search?q=;whoami` | 403 | 932235, 932260, 932340, 932380 |
| `POST /rest/user/login` (`text/plain`, I-3 başka yola sızıyor mu?) | 403 | 920420 |

**Son durum:** 70 istek (62 normal, 8 sınır testi), **0 beklenmeyen sonuç**.

## 8. İzleme

Engelleme modunda yanlış pozitif kullanıcıya 403 olarak yansır. İlk günlerde engellenen istekleri düzenli olarak gözden geçirin:

```bash
# Engellenen istekler ve tetiklenen kurallar
jq -c 'select(.transaction.response.http_code==403)
       | {uri: .transaction.request.uri, method: .transaction.request.method,
          rules: [.transaction.messages[].details.ruleId]}' \
   defense/logs/modsecurity/audit.log
```

Meşru bir istek engellenmişse bu dosyadaki yöntemle ilerleyin: önce kural ID'sini ve eşleşen değişkeni bulun, sonra yalnızca o yol ve o değişken için istisna yazın, ardından bu notu güncelleyin.

## 9. Kapsam dışı

- **Paranoya seviyesi 1.** PL2'ye çıkmak daha fazla yanlış pozitif getirir ve ayrı bir tarama gerektirir.
- **Yanıt tarafı (outbound).** Test sırasında outbound kuralları hiçbir yanıtı engellemedi. Juice Shop'un JSON yanıtları imaj varsayılanı gereği yanıt gövdesi denetimine girmiyor; yalnızca `text/plain`, `text/html` ve `text/xml` denetleniyor.
- **WebSocket ve socket.io içeriği.** WAF, socket.io mesaj içeriğini denetleyemiyor (bkz. I-3).
- **Tarayıcıyla manuel test.** Betik gerçek tarayıcı isteklerini taklit ediyor, ama YP-3'ün gösterdiği gibi her şeyi yakalayamıyor. Yönetici ve muhasebe ekranları da dahil, tarayıcıyla gezinip audit log'u (Bölüm 8) kontrol etmek, kalıcı doğrulama adımı olarak her güncellemeden sonra tekrarlanmalı.
