# Envanter Seçim ve Giriş Noktası Ölçütleri

## Kapsam ve kaynaklar

`inventory/inventory_v1.0.csv`, OWASP Juice Shop için üç ayrı kanıt kümesini bir araya getirir:

- **V001–V016 — Juice Shop challenge'ları:** `inventory/raw/challenges.json` içindeki challenge tanımları ve envanterde belirtilen özellik/uç noktalar.
- **V017–V021 — ZAP:** `inventory/raw/zap_baseline.json` içindeki web tarama bulguları.
- **V022–V036 — Trivy:** `inventory/raw/trivy.json` içindeki `bkimminich/juice-shop:latest` container image bulguları.

Bu 36 kayıt, uygulamanın tüm olası zafiyetlerinin eksiksiz listesi değildir. Raporlanan challenge, web tarama bulgusu ve bağımlılık bulgularından seçilmiş, projede ayrı ayrı izlenen kayıtlardır.

## 36 kaydın seçimi ve birleştirilmesi

### Juice Shop challenge kayıtları (16)

Challenge verisinde açıkça tanımlanan ve envanterde ayrı bir güvenlik problemi olarak izlenen örnekler seçildi. Seçim; enjeksiyon, XSS, erişim kontrolü, dosya/XXE, kimlik doğrulama, yönlendirme ve hata yönetimi gibi farklı saldırı yüzeylerini kapsar. Challenge tanımı tek başına kesin bir URL veya hesap kimliği vermiyorsa, envanterde yalnızca adı geçen özellik yazılır; kanıtın göstermediği endpoint ya da kullanıcı adı uydurulmaz.

V001–V016 kayıtları sırasıyla Login Admin, Database Schema, Reflected XSS, DOM XSS, API-only XSS, View Basket, Manipulate Basket, Admin Registration, Confidential Document, XXE Data Access, Reset Jim's Password, CSRF, Outdated Allowlist, Exposed Credentials, Password Strength ve Error Handling challenge'larıyla eşlenmiştir.

### ZAP kayıtları (5)

`docs/envanter-kalite-kontrol.md` tarama özeti ZAP çıktısında 12 bulgu türü ve 41 örnek bildirir. Aynı bulgunun farklı URL/örnekleri ayrı zafiyet satırlarına çoğaltılmadı; seçilen bulgular bulgu türü başına tek kayıt olarak özetlendi. COEP ve COOP eksikliği aynı güvenlik başlığı kategorisinde V021'de birleştirildi. Böylece V017–V021; CSP, CORS, sunucu sürüm bilgisi, tehlikeli JavaScript fonksiyonları ve COOP/COEP bulgularını temsil eder. Her satırın `entry_evidence` alanında ham ZAP raporundan gözlenen URL bulunur.

### Trivy kayıtları (15)

Trivy'nin CRITICAL ve HIGH öncelikli bulguları ana seçim kümesini oluşturur. Seçilen 15 CVE'nin ham rapordaki dağılımı **6 CRITICAL, 7 HIGH, 1 MEDIUM ve 1 LOW** şeklindedir. V035 (MEDIUM) ve V036 (LOW), envanterdeki CVSS 9.8 değerleriyle Trivy önem dereceleri tutarsız olduğu için mevcut kayıttan çıkarılmadı; bu iki istisnanın belirsizliği `notes` alanında korunmuştur.

V022, aynı CVE için Trivy'nin iki kurulu `jsonwebtoken` sürümünde (`0.1.0` ve `0.4.0`) bulgu vermesini tek CVE satırında birleştirir. Diğer bağımlılık kayıtlarında paket ve kurulu sürüm `entry_evidence` alanında tutulur. Bu kayıtlar için kütüphane zafiyeti, uygulama tarafından dışarıdan erişilebilirlik kanıtı değildir; bu yüzden `entry_point` değeri `dependency` olarak belirlenmiştir.

## Giriş noktası sözlüğü

`entry_point` kapalı listesi:

| Değer | Kullanım |
|---|---|
| `login` | Giriş/kimlik doğrulama formu üzerinden erişilen bulgu |
| `search` | Ürün arama veya arama parametresi |
| `api` | API, sepet veya dosya yükleme özelliği/uç noktası |
| `web` | Yukarıdakiler dışında kalan web sayfası, statik varlık veya web uygulama özelliği |
| `dependency` | Trivy tarafından bildirilen kütüphane/işletim sistemi paketi; dışarıdan erişilebilirliği doğrulanmamıştır |

`entry_evidence` boş bırakılmaz. Kanıt, Juice Shop challenge adı ve özelliği, ZAP raporundaki gözlenen URL veya Trivy raporundaki paket/sürüm bilgisidir. Ham kaynakta endpoint ya da kullanıcı aidiyeti belirtilmediğinde, bu sınırlama açıkça yazılır; tahmin kanıt gibi sunulmaz. İncelenen kaynaklarda kanıtsız bırakılması gereken bir satır bulunmadı.

V014 için `Exposed Credentials` challenge'ı yalnızca istemci tarafına sabitlenmiş, geçerli bir **test hesabı** kimlik bilgisinden söz eder. Challenge verisi belirli bir kullanıcıyı ya da hesabın admin olup olmadığını açıklamaz. Dolayısıyla `notes` alanı bu doğrulama sınırını belirtir ve `grants_capability` değeri `none` bırakılır.

Yetkinlik sütunlarının kapalı sözlüğü ve zafiyet başına eşlemeler için [`yetkinlik-sozlugu.md`](./yetkinlik-sozlugu.md) kullanılır.
