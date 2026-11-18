# Yetkinlik Sözlüğü (Capability Sözlüğü)

## Amaç

Saldırı grafiğindeki "Chains To" (zincirleme) kenarları, iki zafiyetin envanterde yan yana olmasından değil, **birinin kazandırdığı yetkinin diğerinin gerektirdiği yetkinliği karşılamasından** gelmeli. Bu belge, bu yetkinlikleri sabit bir sözlükle tanımlar ve `inventory_v1.0.csv`'ye eklenecek `requires_capability` / `grants_capability` sütunlarının nasıl doldurulacağını gösterir.

Önceki (hatalı) yaklaşım zafiyetleri CSV satır sırasına veya listedeki pozisyonlarına göre zincirliyordu — bu, gerçek bir saldırı mantığı değil, rastgele bir desendi. Bu sözlük bu sorunu çözer: artık **gerçekten mümkün olan** zincirler kuruluyor, geri kalanı bağımsız yol olarak bırakılıyor.

## Sözlük

Serbest metin kullanılmaz, sadece bu kapalı liste geçerlidir (büyük/küçük harf duyarsız, kod `.lower()` ile normalize eder):

| Değer | Anlamı |
|---|---|
| `none` | Özel bir yetkinlik gerekmiyor / kazandırmıyor (varsayılan, çoğu satır için geçerli) |
| `admin_session` | Admin olarak oturum açılmış durumda |
| `password_hashes` | Parola hash'leri (veritabanı dökümü vb. yoluyla) ele geçirilmiş |
| `admin_credentials` | Admin'in düz metin kullanıcı adı/parolası biliniyor |
| `forged_identity` | Herhangi bir kullanıcı (admin dahil) taklit edilebiliyor (örn. sahte token) |
| `stolen_session` | Bir kurbanın oturumu/çerezi ele geçirilmiş |
| `trusted_ip` | Güvenilir/iç IP'den geliyormuş gibi görünülebiliyor |

**Not:** `user_session` (sıradan kullanıcı oturumu) bu sözlükte **kasıtlı olarak yok**. Juice Shop'ta herkes ücretsiz kayıt olabildiği için bu bir "kazanım" değil — bedava elde edilebilen bir şeyi `requires_capability` olarak işaretlemek, var olmayan bir engeli varmış gibi göstermek olur.

## Sütunların kullanımı

`inventory/inventory_v1.0.csv`'ye iki sütun eklenir:

- **`requires_capability`**: Bu zafiyeti sömürmek için saldırganın *önceden* sahip olması gereken yetkinlik. Yoksa `none`.
- **`grants_capability`**: Bu zafiyet sömürülünce saldırganın *yeni kazandığı* yetkinlik. Yoksa `none`.

Çoğu satırda ikisi de `none` olacaktır — bu normaldir, her zafiyetin bir zincire girmesi gerekmez.

## Eşleme kuralı

`generate_edges.py` şu mantıkla çalışır: A zafiyetinin `grants_capability`'si, B zafiyetinin `requires_capability`'sine eşitse, **A → B "Chains To"** kenarı otomatik oluşturulur. B, bu yetkinliği bedava (örn. normal kayıt) elde edebiliyorsa zaten `requires_capability = none` olacağı için zincir aranmaz.

## Envanter için önerilen değerler (36 kayıt)

Aşağıdaki tablo mevcut `inventory_v1.0.csv`'deki CWE ve notlara göre önerilen değerleri gösterir. **İşaretli olanlar (*) K2 tarafından doğrulanmalı**, diğerleri CVSS vektörü ve zafiyet tipinden yüksek güvenle çıkarıldı.

| vuln_id | requires_capability | grants_capability | Not |
|---|---|---|---|
| V001 | none | admin_session | SQLi ile admin login bypass |
| V002 | none | password_hashes | UNION SQLi, veritabanı dökümü |
| V003 | none | stolen_session | Reflected XSS |
| V004 | none | stolen_session | DOM XSS |
| V005 | none | stolen_session | Stored XSS |
| V006 | none | none | IDOR (veri okuma, zincir kaynağı değil) |
| V007 | none | none | IDOR (veri değiştirme) |
| V008 | none | admin_session | Mass Assignment ile doğrudan admin kaydı |
| V009 | none | none | Dizin listeleme |
| V010 | none | none | XXE dosya okuma |
| V011 | none | none | Zayıf güvenlik sorusu (yalnızca "Jim" hesabı) |
| V012 | none | none | CSRF |
| V013 | none | none | Açık yönlendirme |
| V014 | none | none | İstemci tarafında sabitlenmiş test hesabı kimlik bilgileri; challenge verisi kullanıcıyı veya admin olup olmadığını belirtmiyor |
| V015 | none | admin_session | Zayıf admin parolası, brute force |
| V016 | none | none | Ayrıntılı hata mesajı |
| V017 | none | none | CSP başlığı yok (enabler, kendi başına kazanım değil) |
| V018 | none | none | CORS yanlış yapılandırması |
| V019 | none | none | Sürüm bilgisi sızıntısı |
| V020 | none | none | Tehlikeli JS fonksiyonları |
| V021 | none | none | COOP/COEP eksik |
| V022 | none | forged_identity | JWT algoritma karışıklığı |
| V023 | none | none | Prototype pollution |
| V024 | none | none | Command injection (doğrudan RCE hedefine gidiyor) |
| V025 | **password_hashes** | admin_credentials | Zayıf PBKDF2 — V002'nin kazandırdığı hash'leri kırılabilir hale getiriyor |
| V026 | none | none | Zayıf rastgelelik |
| V027 | none | none | Path traversal (zip slip, doğrudan RCE hedefine gidiyor) |
| V028 | none | trusted_ip | IP spoofing / güven zinciri |
| V029 | none | none | Tar unicode normalizasyonu |
| V030 | none | admin_session | Yetkilendirme atlatma (express-jwt) |
| V031 | none | none | Path traversal (moment) |
| V032 | none | none | ReDoS |
| V033 | none | none | DoS (ws) |
| V034 | none | none | DoS (multer) |
| V035 | none | none | Heap taşması |
| V036 | none | none | Heap taşması |

## Bu tablodan çıkan gerçek zincir

Bu değerlerle `generate_edges.py` çalıştırıldığında ortaya çıkan **tek** "Chains To" kenarı:

```
V002 (UNION SQLi → password_hashes) → V025 (zayıf PBKDF2, password_hashes gerektirir)
```

Bu az sayıda gibi görünse de doğru olan budur: 36 zafiyetin geri kalanı bağımsız giriş→zafiyet→hedef yolları olarak kalır, bu da gerçek bir saldırı yüzeyinde beklenen bir durumdur. V014'ün kaynağı yalnızca kimlik bilgilerinin istemci tarafında sabitlenmiş, geçerli bir test hesabına ait olduğunu söylüyor; hangi kullanıcıya ait olduğunu veya hesabın admin olduğunu doğrulamıyor. Bu nedenle V014'e `admin_credentials` atanmadı. Hesap aidiyeti güvenilir kanıtla doğrulanırsa envanter ve bu eşleme yeniden değerlendirilmelidir.
