# WAF engelleme modu notu (S3-K5)

**Tarih:** 17.11.2026
**Kapsam:** `defense/docker-compose.yml` içindeki `waf` servisi (`owasp/modsecurity-crs:4.30.0-nginx-202610180210`, CRS 4.30.0) ve arkasındaki Juice Shop
**Sonuç:** WAF tespit modundan (DetectionOnly) engelleme moduna (On) geçirildi. Normal kullanımda üç yanlış pozitif kaynağı bulundu. Üçü de dar kapsamlı istisnalarla giderildi. Saldırı örnekleri 403 alıyor, test edilen 62 normal istek ise sorunsuz geçiyor. `test-waf.sh` envanterdeki V001, V003 ve V005'i de kapsıyor. V003'ü CRS yakalamıyordu; bunun için bir sanal yama (SY-1) eklendi.

**Güncelleme (21.11.2026, ek savunma):** Altı sanal yama daha (SY-2…SY-7: V008, V013, V010, V012, V002, V001) ve nginx'te güvenlik başlıkları (V017, V018, V021), genel hata sayfası (V016) ve hız sınırı (V015) eklendi. Ayrıntı: Bölüm 7 ve Bölüm 11. Son durum: `test-waf.sh` 41/0, `test-juice-flows.py` 70/0.

---

## 1. Yapılan değişiklikler

| Dosya | Değişiklik |
|---|---|
| `defense/docker-compose.yml` | `MODSEC_RULE_ENGINE: DetectionOnly` değeri `"On"` yapıldı. |
| `defense/docker-compose.yml` | WAF imajı `owasp/modsecurity-crs:nginx` (kayan etiket) yerine `owasp/modsecurity-crs:4.30.0-nginx-202610180210` olarak sabitlendi (Bölüm 3). |
| `defense/docker-compose.yml` | `ALLOWED_METHODS: "GET HEAD POST OPTIONS"` açıkça yazıldı. Bu CRS'in zaten varsayılan değeri; davranış değişmedi, politika görünür hale geldi. |
| `defense/docker-compose.yml` | İstisna dosyası salt okunur bağlandı: `./modsecurity/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` → `/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` |
| `defense/modsecurity/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` | **Yeni.** Juice Shop istisnaları (kural ID 10010, 10011, 10012, 10020, 10030). |
| `defense/modsecurity/REQUEST-900-VIRTUAL-PATCHES-JUICESHOP.conf` | **Yeni.** Sanal yama SY-1 (kural ID 10100, V003). Compose'da istisna dosyasının yanına bağlandı. |
| `defense/test-waf.sh` | V001, V003 ve V005 için saldırı + zararsız kontrol çiftleri eklendi. Her satır beklenen kodu gösteriyor; betik çıkış kodu döndürüyor (0 = hepsi beklenen sonuçta). |
| `defense/test-juice-flows.py` | **Yeni.** Normal kullanıcı akışlarını ve istisnaların sınırını test eden betik (yalnızca standart kütüphane). |

Diğer ayarlar değişmedi: PL1, blocking PL1, inbound eşiği 5, outbound eşiği 4, audit log JSON.

## 2. Devreye alma

```bash
cd defense
docker compose pull waf                              # sabitlenen CRS 4.30.0 imajı
docker compose up -d --force-recreate waf suricata
./test-waf.sh                    # 12 istek, 0 beklenmeyen sonuç, çıkış kodu 0
python3 test-juice-flows.py      # 0 beklenmeyen sonuç, çıkış kodu 0
```

`suricata` servisi `network_mode: "service:waf"` ile WAF'ın ağ arayüzünü paylaşıyor. WAF container'ı yeniden oluşturulduğunda Suricata'nın da yeniden oluşturulması gerekir; aksi halde Suricata eski ve artık var olmayan bir ağ arayüzünü dinlemeye devam eder. Komuttaki `suricata` bu yüzden var.

**Geri alma:** `MODSEC_RULE_ENGINE: DetectionOnly` yapıp aynı komutu çalıştırmak yeterli.

**Satır sonları:** `.gitattributes` (repo kökü, `s3k5/wafengelleme` dalı, commit `43443f4`), `*.conf`, `*.sh`, `*.py`, `*.yml`, `*.rules` ve `*.template` dosyalarını her zaman LF tutar. Windows'ta CRLF'ye çevrilen bir ModSecurity kural dosyası (satır sonundaki `\` devam karakteri bozulur) WAF'ın açılmasını engeller; CRLF'li bir bash betiği de çalışmaz. Kontrol: `git check-attr eol -- defense/test-waf.sh` komutu `eol: lf` göstermeli. Dal `main`'e birleştirilene kadar `main` dalında bu dosya yoktur.

## 3. Test ortamı

Testlerin yapıldığı çalışma ortamı Docker Hub'a ve ghcr.io'ya erişemedi. Bu yüzden container yerine aynı bileşenlerle eşdeğer bir kurulum kullanıldı:

| Bileşen | Lab (compose) | Test edilen |
|---|---|---|
| CRS | `owasp/modsecurity-crs:4.30.0-nginx-202610180210` → CRS **4.30.0** | CRS **4.30.0** (git tag) |
| ModSecurity | v3 (imajın içinden) | libmodsecurity 3.0.12 + ModSecurity-nginx 1.0.3 |
| nginx | nginx-unprivileged 1.30 | nginx 1.24 |
| Juice Shop | `bkimminich/juice-shop` (latest); `/rest/admin/application-version` → **20.2.0** (17.11.2026) | Juice Shop **v20.4.0** (GitHub sürüm paketi; aynı uç nokta `20.4.0-SNAPSHOT` döndürüyor) |
| CRS ayarları | PL1 / blocking PL1 / 5 / 4, allowed_methods varsayılan | Aynı (crs-setup içinde 900200 dahil) |
| ModSecurity ayarları | İmaj varsayılanları | İmaj şablonu taklit edildi: istek ve yanıt gövdesi denetimi açık, JSON/XML gövde işlemcileri, gövde ayrıştırma hatasında 400 |

**Lab ile test ortamının karşılaştırması (17.11.2026):**
- **CRS:** İkisinde de **4.30.0**. Lab'da çalışan imajda `grep -o 'OWASP_CRS/4[0-9.]*' …/REQUEST-901-INITIALIZATION.conf` ile doğrulandı. İmajı sabitlemek lab'daki CRS'i değiştirmiyor, yalnızca kilitliyor.
- **Juice Shop:** Lab **20.2.0**, test ortamı **20.4.0**. Fark incelendi:
  - I-1'in uç nokta listesi 20.4.0 ön yüzünden çıkarılmıştı. 20.2.0'ın ön yüzünün kullandığı bütün PUT, PATCH ve DELETE çağrıları bu listede. Tek fark `DELETE /rest/passkey/credentials/{id}`: yalnızca 20.4.0'da var. Lab'da bu yol olmadığı için istisna orada etkisiz (404).
  - V003 açığı (`routes/trackOrder.ts` içindeki `$where`) ve sipariş numarası biçimi (`routes/order.ts`) 20.2.0'da aynı. SY-1 lab için de geçerli.
  - Lab'da `test-juice-flows.py` 70/70 geçti (aşağıda).
- **nginx:** Lab 1.30, test ortamı 1.24. Kurallar nginx'ten bağımsız.
- **Öneri:** Juice Shop imajı da kayan `latest` etiketinde. Aynı gerekçeyle lab sürümüne (`bkimminich/juice-shop:v20.2.0`) sabitlenmesi önerilir; aksi halde bir `pull` I-1 listesini ve SY-1'in biçim varsayımını sessizce geçersiz kılabilir.

**Neden imaj sabitlendi:** İstisnalar (I-1..I-3) ve sanal yama, CRS kural numaralarına ve kuralların davranışına bağlı. Kayan `nginx` etiketi her `docker compose pull`'da CRS'i sessizce yükseltebilir. O durumda bir istisna artık doğru kuralı hedeflemeyebilir (yanlış pozitif geri gelir) ya da bir kuralın davranışı değişebilir (saldırı geçer). Bu imajda CRS sürümünü sabitleyen tarihsiz bir etiket yok; CRS'in güncel sürümü yalnızca `<CRS>-nginx-<derleme zamanı>` biçiminde yayınlanıyor. Etiket, Docker Hub'ın etiket sayfasından alındı (17.11.2026). CRS yükseltmesi bilinçli yapılmalı: etiketi değiştir, `test-waf.sh` ve `test-juice-flows.py`'ı çalıştır, bu notu güncelle.

**Lab doğrulaması (17.11.2026, `s3k5/wafengelleme` dalı):** Compose ile devreye alındıktan sonra container'da `SecRuleEngine On` görüldü, istisna kuralları yüklendi ve nginx logunda hata yok. `test-waf.sh` normal trafikte 200, 4 saldırı örneğinde 403 döndü. `test-juice-flows.py` (ilk sürüm) sonucu: 68 istek, 0 beklenmeyen sonuç.

Ardından tarayıcıyla yapılan elle testte audit log'da YP-3 (socket.io POST, 920420) görüldü. Betik bu isteği kapsamıyordu. I-3 istisnası eklendi ve betiğe socket.io POST testi eklendi; güncel sonuç: 70 istek, 0 beklenmeyen sonuç.

Aynı tarayıcı testinde sepet boş görünüyordu. Audit log'da sepet isteklerine ait bir engelleme yoktu; sebep, Juice Shop yeniden başlamadan (veritabanı sıfırlanmadan) önce açılmış bir tarayıcı oturumuydu. Çıkış yapıp tekrar giriş yapınca sepet normal çalıştı. **WAF kaynaklı değil.**

## 4. `test-waf.sh` sonuçları

Her saldırı satırının yanında aynı uç noktaya giden zararsız bir kontrol isteği var. Kontrol isteği, uç noktanın kendisinin engellenmediğini gösteriyor; böylece 403'ün saldırı içeriğinden kaynaklandığı belli oluyor.

| Envanter | İstek | DetectionOnly (önce) | On (sonra) | Tetiklenen kurallar (On) → anomali puanı |
|---|---|---|---|---|
| — | ana sayfa | 200 | **200** | — |
| — | ürün listesi (`q=apple`) | 200 | **200** | — |
| — | SQLi, arama (`' OR 1=1--`) | **500** (SQL hatası) | **403** | 942100 → **5 (tam eşik)** |
| — | XSS, arama (`<script>…`) | 200 | **403** | 941100, 941110, 941160, 941390 → 20 |
| — | Path traversal | 200 | **403** | 930100, 930110, 930120, 932160 → 30 |
| — | Scanner UA (`sqlmap`) | 200 | **403** | 913100 → **5 (tam eşik)** |
| V001 | Kontrol: giriş, yanlış şifre (JSON POST) | 401 | **401** | — |
| V001 | SQLi, giriş `email` alanı (`' OR 1=1--`) | **200**: `admin@juice-sh.op` olarak giriş | **403** | 942100 → **5 (tam eşik)** |
| V003 | Kontrol: sipariş takibi, geçerli numara | 200 | **200** | — |
| V003 | NoSQLi, yol içinde (`' \|\| true \|\| '`) | **200**: başka kullanıcıların siparişleri (1 yerine 3) | **403** | **SY-1 (10100)**; CRS tek başına yakalamıyor |
| V005 | Kontrol: `PUT /api/Products/999999`, zararsız açıklama | 404 | **404** | — |
| V005 | XSS, `PUT /api/Products/999999` `description` alanı | 404 (WAF'tan geçti) | **403** | 941100, 941160, 941170, 941210, 941390 → 25 |

**Sonuç (On):** 12 istek, 0 beklenmeyen sonuç.

**Eşik notu:** SQLi isteklerinin ikisi de (arama ve giriş) yalnızca tek bir kritik kuralla (942100, libinjection) yakalanıyor ve toplam puan **tam olarak** inbound eşiğine (5) eşit. Scanner UA için de durum aynı. Yani güvenlik payı yok:
- Eşik 6'ya ya da üstüne çıkarılırsa (yanlış pozitifleri azaltmak için sık yapılan bir ayar) bu üç istek geçer.
- 942100 bir istisnayla bu alanlardan çıkarılırsa da geçerler.
- Eşik ya da bu alanlara dokunan bir istisna değişirse `test-waf.sh` mutlaka tekrar çalıştırılmalı. Bu satırlar böyle bir değişikliği yakalamak için var.

> **Güncelleme (21.11.2026):** SQLi için güvenlik payı sorunu SY-6 (V002) ve SY-7 (V001) ile giderildi. Bu iki kural puanlamaya katılmıyor, doğrudan engelliyor. Eşik 6'ya çıkarılarak denendi: arama ve giriş SQLi'si (JSON ve form gövdesi) yine 403 aldı (`inventory/raw/after_controls/test-waf-esik6.log`). SY-7'nin ilk sürümü (`ARGS_POST`) eşik 6'da JSON gövdesini kaçırmıştı (200, admin girişi); ModSecurity v3 JSON alanlarını `ARGS`'a koyduğu için düzeltildi. Scanner UA satırı hâlâ tam eşikte (913100, 5 puan); envanterde bir zafiyete bağlı değil.

**V003 ve sanal yama:** CRS, PL1'de yol içindeki NoSQL enjeksiyonunu yakalamıyor. Sanal yama eklenmeden önce engelleme modunda da istek 200 aldı ve siparişler sızdı. Varyasyonlara bakıldığında `sleep()` içeren yük 403 alıyordu, ama boolean (`' || 1==1 || '`) ve `$where` yükleri geçiyordu. Ayrıntı: Bölüm 7.

**V005 ve I-1:** I-1 bu yolda PUT metodunu açıyor, ancak gövdenin içeriği CRS'in bütün kurallarıyla denetlenmeye devam ediyor (puan 25). Juice Shop bu uç noktada yetki istemiyor; zararsız bir PUT gerçek bir ürünü değiştirir. Bu yüzden iki istek de var olmayan ürüne (`999999`) gönderiliyor; WAF kapalı olsa bile lab verisi değişmiyor.

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

- **Neden site geneli `ALLOWED_METHODS` değil:** `ALLOWED_METHODS="… PUT PATCH DELETE"` yazmak daha kolay olurdu. Ama o zaman `PUT /api/Users/1` gibi ön yüzün hiç kullanmadığı yollar da metod politikasından geçerdi. Uç nokta bazlı izinle bu istekler hâlâ 403 alıyor (bkz. Bölüm 8).
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

## 7. Sanal yamalar

İstisnalar CRS'i gevşetiyor (yanlış pozitif). Sanal yamalar ise CRS'in kaçırdığı, bilinen bir açığa özel kural ekliyor. Ayrı dosyada duruyorlar: `REQUEST-900-VIRTUAL-PATCHES-JUICESHOP.conf`. İmaj bu dosyayı istisna dosyasından sonra, CRS kurallarından önce yüklüyor.

### SY-1: Sipariş takibi, NoSQL enjeksiyonu (V003) | ID 10100

- **Açık:** `/rest/track-order/:id` parametresi doğrudan bir `$where` sorgusuna giriyor (`routes/trackOrder.ts`): `this.orderId === '${id}'`. `' || true || '` gibi bir değer bütün siparişleri döndürüyor.
- **Yöntem (pozitif model):** Saldırı imzası aramak yerine geçerli girdi tanımlanıyor. Juice Shop sipariş numarasını `hash(email).slice(0,4) + '-' + randomHex(16)` ile üretiyor (`routes/order.ts`, `data/datacreator.ts`). Bu yüzden yalnızca `^/rest/track-order/[0-9a-f]{4}-[0-9a-f]{16}$` kabul ediliyor; gerisi doğrudan 403 alıyor (anomali puanına girmiyor).
- **Atlatmaya karşı:** Express yolları büyük/küçük harf ayırmadığı için yol önce `%xx` çözülüyor, `//` ve `./` normalize ediliyor ve küçük harfe çevriliyor. Test edildi; hepsi 403 aldı:
  - `/REST/Track-Order/…`
  - `//rest/track-order/…`
  - `/rest/./track-order/…`
  - geçerli numaranın sonuna eklenmiş yük
  - `$where` ve `1==1` varyasyonları
- **Yanlış pozitif kontrolü:**
  - Geçerli numaralar büyük/küçük harften bağımsız olarak geçiyor.
  - `test-juice-flows.py` gerçek bir siparişin takibini yapıyor: 70/70 geçti.
  - Tek yan etki: sonu `/` ile biten geçerli bir numara da 403 alıyor. Ön yüz bu biçimi kullanmıyor.
- **Sınırlama:** Bu yama açığı kapatmıyor, yalnızca WAF önünde maskeliyor; kalıcı çözüm uygulamada `$where` yerine parametreli sorgu kullanmak. Juice Shop güncellenip sipariş numarası biçimi değişirse sipariş takibi 403 almaya başlar. Audit log'da 10100 görülürse regex güncellenmeli.

### SY-2: Kayıtta rol atama (V008) | ID 10110

- **Açık:** `POST /api/Users` gövdesi doğrudan Sequelize `User` modeline yazılıyor; gövdeye `"role":"admin"` eklenince yönetici hesabı açılıyor (mass assignment). Kayıt formu bu alanı hiç göndermiyor.
- **Kural:** `POST /api/users` (yol normalize, küçük harf) isteğinde argüman adı `role` ile bitiyorsa (JSON'da `json.role`) 403. phase:2, CRS'in JSON işlemcisinden sonra.
- **Test:** `role=admin` 403, normal kayıt 201.

### SY-3: Yönlendirme izin listesi (V013) | ID 10120, 10121

- **Açık:** `/redirect?to=` hedefi `lib/insecurity.ts`'te `url.includes(izinli)` ile denetleniyor: izinli bir adresi *içeren* her adrese yönlendiriyor. Listede arayüzün artık kullanmadığı üç kripto para adresi de duruyor.
- **Kural (pozitif model):** Tek bir `to` parametresi zorunlu (10120); değer arayüzün kullandığı beş adresten biriyle **birebir** aynı olmalı (10121: github, iki spreadshirt, stickeryou, leanpub).
- **Test:** izinli adres 302; kripto adresi ve izinli adresi içeren hedef 403.

### SY-4: XML dosya yükleme, XXE (V010) | ID 10130

- **Açık:** `routes/fileUpload.ts` dosyayı yalnızca adı `.xml` ile bitiyorsa dış varlıkları açık bir XML ayrıştırıcıyla işliyor. Arayüz yalnızca PDF ve ZIP yüklüyor; XML yükleme uygulamada da "kullanımdan kalktı" olarak işaretli.
- **Kural:** `/file-upload` isteğinde yüklenen dosyanın adı `.xml` ile bitiyorsa 403. İçeriğe bakmaya gerek yok, karar dosya adına göre (uygulama da öyle karar veriyor).
- **Test:** PDF 204, XML (zararsız içerik) 403.

### SY-5: Profil güncellemede CSRF (V012) | ID 10140

- **Açık:** `POST /profile` yalnızca oturum çerezine bakıyor; isteğin hangi siteden geldiğini denetlemiyor.
- **Kural:** `Origin` başlığı varsa ve lab'ın kendi adreslerinden biri değilse (`localhost`, `127.0.0.1`, `host.docker.internal`; `:8080` ile ya da portsuz) 403. Tarayıcılar başka siteden gelen POST'a her zaman `Origin` ekler.
- **Test:** girişli oturum, kendi sitemizden 302; yabancı Origin 403.
- **Sınırlama:** `Origin` göndermeyen istemciler (curl gibi) kapsam dışı; bunlar CSRF senaryosu değil.

### SY-6: Ürün aramasında SQLi (V002) | ID 10150 ve SY-7: Giriş formunda SQLi (V001) | ID 10160

- **Açık:** `routes/search.ts` ve `routes/login.ts` girdiyi SQLite'ta tek tırnaklı bir metnin içine koyuyor (`LIKE '%${q}%'`, `email = '${email}'`). SQLite'ta ters eğik çizgi kaçış karakteri değil; metinden çıkmanın tek yolu tek tırnak.
- **Kural:** aramada `q`, girişte `email` alanında tek tırnak (`\x27`) varsa doğrudan 403. JSON (`\u0027` dahil), form gövdesi ve dizi biçimleri (`q[]=`, `email[]=`) kapsanıyor.
- **Yanlış pozitif:** Hiçbir ürün adında tek tırnak yok (yalnızca çift tırnak); arayüz aramayı `q=` ile yapıp tarayıcıda süzüyor. Seed kullanıcıların e-postalarında tek tırnak yok.
- **Test:** arama SQLi 403, çift tırnaklı zararsız arama 200; giriş SQLi JSON ve form gövdesinde 403. Eşik 6'da da 403 (Bölüm 4, eşik notu).
- **Söz dizimi notları:** Operatörde çıplak `'` ve değişken seçicide `$|\[` ModSecurity ayrıştırıcısında söz dizimi hatası veriyor (WAF açılmıyor); kurallar bu yüzden `\x27` ve sade seçicilerle (`ARGS_GET:/^q/`, `ARGS:/email/`) yazıldı.

Bütün sanal yamalar için aynı sınırlama geçerli: açığı kapatmıyorlar, WAF önünde maskeliyorlar. Kalıcı çözüm uygulama kodunda. Juice Shop sürümü değişirse `test-waf.sh` mutlaka tekrar çalıştırılmalı.

## 8. İstisnaların sınır testleri

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

## 9. İzleme

Engelleme modunda yanlış pozitif kullanıcıya 403 olarak yansır. İlk günlerde engellenen istekleri düzenli olarak gözden geçirin:

```bash
# Engellenen istekler ve tetiklenen kurallar
jq -c 'select(.transaction.response.http_code==403)
       | {uri: .transaction.request.uri, method: .transaction.request.method,
          rules: [.transaction.messages[].details.ruleId]}' \
   defense/logs/modsecurity/audit.log
```

Meşru bir istek engellenmişse bu dosyadaki yöntemle ilerleyin: önce kural ID'sini ve eşleşen değişkeni bulun, sonra yalnızca o yol ve o değişken için istisna yazın, ardından bu notu güncelleyin.

## 10. Kapsam dışı

- **Paranoya seviyesi 1.** PL2'ye çıkmak daha fazla yanlış pozitif getirir ve ayrı bir tarama gerektirir.
- **Yanıt tarafı (outbound).** Test sırasında outbound kuralları hiçbir yanıtı engellemedi. Juice Shop'un JSON yanıtları imaj varsayılanı gereği yanıt gövdesi denetimine girmiyor; yalnızca `text/plain`, `text/html` ve `text/xml` denetleniyor.
- **WebSocket ve socket.io içeriği.** WAF, socket.io mesaj içeriğini denetleyemiyor (bkz. I-3).
- **Tarayıcıyla manuel test.** Betik gerçek tarayıcı isteklerini taklit ediyor, ama YP-3'ün gösterdiği gibi her şeyi yakalayamıyor. Yönetici ve muhasebe ekranları da dahil, tarayıcıyla gezinip audit log'u (Bölüm 9) kontrol etmek, kalıcı doğrulama adımı olarak her güncellemeden sonra tekrarlanmalı.

## 11. Ek savunma: nginx kontrolleri (21.11.2026)

ModSecurity dışındaki kontroller WAF konteynerindeki nginx'te: `defense/nginx/default.conf.template`. WAF modundan (On/DetectionOnly) bağımsız çalışırlar.

| Kontrol | Zafiyet | Ne yapıyor | Kanıt |
|---|---|---|---|
| CSP | V017 | Satır içi betiklere yalnızca sha256 özetiyle izin; `'unsafe-inline'` betik yok. Juice Shop'un kendi CSP'si olan yanıtlarda (`/profile`) onunki korunuyor. | ZAP 10038 kayboldu |
| CORS | V018 | Juice Shop'un her yanıta eklediği `Access-Control-Allow-Origin: *` siliniyor (uygulama tek kökenli). | ZAP 10098 kayboldu |
| COOP / COEP / CORP | V021 | `same-origin` / `require-corp` / `same-origin` | ZAP 90004 kayboldu |
| Genel hata sayfası | V016 | 500, 502, 503, 504, 406, 410 yanıtlarında yığın izi yerine `{"error":"Istek islenemedi."}`; durum kodu korunuyor. | test-waf: yığın izi yok |
| Hız sınırı | V015 | `POST /rest/user/login` ve `/rest/user/reset-password`: dakikada 10, anlık 20 pay, aşılınca 429. Anahtar bağlantı adresi (`X-Forwarded-For` ile atlatılamaz); büyük/küçük harf duyarsız. | test-waf: 30 denemede 19 tanesi 429 |

**Doğrulama:**
- `test-waf.sh` 41/0, `test-juice-flows.py` 70/0 (`inventory/raw/after_controls/`).
- Juice Shop v20.2.0'ın resmi derlemesi önünde aynı nginx yapılandırmasıyla tarayıcıda 25 sayfa gezildi: CSP ihlali ve sayfa hatası yok; ana sayfa ve skor tablosu ekran görüntüleri başlıklı/başlıksız piksel piksel aynı; socket.io WebSocket bağlantısı ve "challenge çözüldü" bildirimi çalışıyor.
- ZAP baseline (WAF arkasında): `inventory/raw/after_controls/zap_baseline.json` (önceki tarama `zap_baseline_s5.json`).

**CSP özetleri imaja bağlı.** Üç özet Juice Shop v20.2.0 (`sha256:8739101a…`) sayfalarına ait: `index.html`'deki cookieconsent betiği, `/promotion`'daki altyazı betiği ve stil dosyasını açan `onload="this.media='all'"`. İmaj değişirse `test-waf.sh`'taki "CSP özetleri" satırları HATA verir; özetler yeniden hesaplanır.

**Kabul edilen eksikler:**
- **CSP (V017 → azaltır):** ZAP 10055 iki Medium uyarı veriyor: `script-src 'unsafe-hashes'` (yalnızca yukarıdaki tek `onload` satırına izin veriyor) ve `style-src 'unsafe-inline'` (Angular Material çalışırken stil ekliyor). İkisini kaldırmak Juice Shop'un kodunu değiştirmeyi gerektiriyor. İlk sürümdeki `connect-src ws: wss:` (ZAP "Wildcard Directive") kaldırıldı; `'self'` aynı adresin WebSocket'ini de kapsıyor.
- **Hata sayfası (V016 → azaltır):** 401 ve 403 yanıtlarına dokunulmadı, çünkü arayüz bu yanıtların metnini gösteriyor (örneğin giriş ekranındaki "Invalid email or password"). Bu yanıtlarda Juice Shop'un yığın izi kalıyor.
- **Hız sınırı (V015 → azaltır, V011 → etkisiz):** Kaba kuvvet dakikada 10 denemeye iniyor, ama `admin123` küçük listelerde de var; sınır yalnızca yavaşlatıyor. V011'de asıl saldırı cevabı internetten bulup tek istekte girmek; hız sınırı bunu durdurmuyor. Lab'da bilgisayardan gelen bütün istekler aynı Docker ağ geçidi adresinden göründüğü için sınır tüm istemciler için ortak. `test-waf.sh`'taki hız sınırı testi en sonda; bitince giriş istekleri yaklaşık 2 dakika 429 alabilir, bu yüzden `test-juice-flows.py` önce çalıştırılır.
- **ZAP'ın yeni gördüğü IAM bulguları:** `_oauth2_proxy_csrf` çerezinde `SameSite` yok (10054) ve oturum yanıtı bilgisi (10112). İkisi de oauth2-proxy'den geliyor, bu değişiklikten değil.

**Test betiği düzeltmesi:** `test-juice-flows.py` tarayıcı gibi `Accept-Encoding: gzip` gönderiyor, ama sıkıştırılmış yanıtı açmıyordu. Yorum listesi 1 KB'ı geçince JSON okunamıyor ve "yorumu düzenle/beğen" adımları sessizce atlanıyordu (68/70). Betik artık yanıtı açıyor; bulunamayan yorum da HATA sayılıyor.
