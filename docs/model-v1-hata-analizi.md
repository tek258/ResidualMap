# Model v1 Hata Analizi Raporu (`phi3:mini`)

## 1. Genel Bakış ve Kapsam
Bu doküman, Issue #80 kapsamında Model v1 (`ai/model_v1_local_llm.py`) çıktılarının K2 uzman etiketleriyle (`ai/expert_labels.csv`) karşılaştırılmasını, uyuşmayan kayıtların gerekçe bazlı incelemesini, ortak hata kalıplarını ve tekrarlı çalıştırma tutarlılık ölçümlerini içerir.

- **Toplam Envanter Kaydı:** 36
- **İşlenen Kayıt:** 35 (Atlanan: 1 - `V014`)
- **Eşleşen Kayıt:** 13 / 35 (%37.14)
- **Uyuşmayan / Atlanan Kayıt:** 23

---

## 2. v1 Skorları ve Uzman Etiketleri Karşılaştırma Tablosu (Tüm Kayıtlar)

| Vuln ID | Bileşen / Başlık | CVSS | EPSS | v1 Skor | v1 Etiket | K2 Etiket | Durum |
|---|---|---:|---:|---:|---|---|---|
| V001 | SQL Injection - login formu (Login Admin) | 9.8 | bilinmiyor | 9.80 | Yüksek | Kritik | Uyuşmadı |
| V002 | UNION SQL Injection - urun arama (Database Schema) | 7.5 | bilinmiyor | 7.50 | Yüksek | Yüksek | Eşleşti |
| V003 | Reflected XSS - siparis takip | 6.1 | bilinmiyor | 6.10 | Yüksek | Orta | Uyuşmadı |
| V004 | DOM XSS - arama kutusu | 6.1 | bilinmiyor | 6.10 | Yüksek | Orta | Uyuşmadı |
| V005 | API-only (Stored) XSS | 6.1 | bilinmiyor | 6.10 | Yüksek | Orta | Uyuşmadı |
| V006 | IDOR - baska kullanicinin sepetini gorme (View Basket) | 6.5 | bilinmiyor | 6.50 | Yüksek | Orta | Uyuşmadı |
| V007 | IDOR - baska kullanicinin sepetini degistirme (Manipulate Basket) | 6.5 | bilinmiyor | 6.50 | Yüksek | Orta | Uyuşmadı |
| V008 | Mass Assignment - admin kaydi (Admin Registration) | 9.8 | bilinmiyor | 9.80 | Yüksek | Kritik | Uyuşmadı |
| V009 | Dizin listeleme - /ftp gizli dokuman (Confidential Document) | 7.5 | bilinmiyor | 7.50 | Yüksek | Yüksek | Eşleşti |
| V010 | XXE - dosya okuma (XXE Data Access) | 6.5 | bilinmiyor | 6.50 | Yüksek | Yüksek | Eşleşti |
| V011 | Zayif guvenlik sorusu ile sifre sifirlama (Reset Jim's Password) | 7.4 | bilinmiyor | 7.40 | Yüksek | Orta | Uyuşmadı |
| V012 | CSRF - profil islemi | 4.3 | bilinmiyor | 4.30 | Yüksek | Düşük | Uyuşmadı |
| V013 | Acik yonlendirme - eski allowlist (Outdated Allowlist) | 6.1 | bilinmiyor | 6.10 | Yüksek | Orta | Uyuşmadı |
| V014 | Acikta kalan kimlik bilgileri (Exposed Credentials) | 7.5 | bilinmiyor | - | ATLANDI (HTTP 500) | Orta | Uyuşmadı |
| V015 | Zayif admin parolasi - brute force (Password Strength) | 8.1 | bilinmiyor | 8.10 | Yüksek | Yüksek | Eşleşti |
| V016 | Ayrintili hata mesaji (Error Handling) | 5.3 | bilinmiyor | 5.30 | Yüksek | Düşük | Uyuşmadı |
| V017 | CSP basligi yok | 4.2 | bilinmiyor | 4.20 | Yüksek | Düşük | Uyuşmadı |
| V018 | Cross-Domain Misconfiguration (genis CORS) | 3.1 | bilinmiyor | 3.10 | Yüksek | Düşük | Uyuşmadı |
| V019 | Server basliginda surum bilgisi sizintisi | 5.3 | bilinmiyor | 5.30 | Yüksek | Düşük | Uyuşmadı |
| V020 | Tehlikeli JS fonksiyonlari | 4.2 | bilinmiyor | 4.20 | Yüksek | Düşük | Uyuşmadı |
| V021 | COOP/COEP basliklari eksik | 3.1 | bilinmiyor | 3.10 | Yüksek | Düşük | Uyuşmadı |
| V022 | jsonwebtoken 0.1.0 / 0.4.0 - CVE-2015-9235 | 9.8 | 0.08524 | 9.80 | Kritik | Yüksek | Uyuşmadı |
| V023 | lodash 2.4.2 - CVE-2019-10744 | 9.1 | 0.05006 | 9.10 | Kritik | Yüksek | Uyuşmadı |
| V024 | lodash 2.4.2 - CVE-2021-23337 | 7.2 | 0.21333 | 7.20 | Yüksek | Yüksek | Eşleşti |
| V025 | crypto-js 3.3.0 - CVE-2023-46233 | 9.1 | 0.00635 | 9.10 | Kritik | Yüksek | Uyuşmadı |
| V026 | crypto-js 3.3.0 - CVE-2026-71851 | 9.0 | 0.0055 | 9.00 | Yüksek | Yüksek | Eşleşti |
| V027 | decompress 4.2.1 - CVE-2026-101894 | 9.1 | 0.00814 | 9.10 | Kritik | Yüksek | Uyuşmadı |
| V028 | proxy-addr 2.0.7 - CVE-2026-90711 | 9.1 | 0.00332 | 9.10 | Yüksek | Yüksek | Eşleşti |
| V029 | tar 6.2.1 - CVE-2026-23950 | 8.8 | 0.00257 | 8.80 | Yüksek | Yüksek | Eşleşti |
| V030 | express-jwt 0.1.3 - CVE-2020-15084 | 7.7 | 0.01221 | 7.70 | Yüksek | Yüksek | Eşleşti |
| V031 | moment 2.0.0 - CVE-2022-24785 | 7.5 | 0.13904 | 7.50 | Yüksek | Yüksek | Eşleşti |
| V032 | moment 2.0.0 - CVE-2017-18214 | 7.5 | 0.03649 | 7.50 | Yüksek | Yüksek | Eşleşti |
| V033 | ws 7.4.6 - CVE-2024-37890 | 7.5 | 0.01346 | 7.50 | Yüksek | Yüksek | Eşleşti |
| V034 | multer 1.4.5-lts.2 - CVE-2025-47944 | 7.5 | 0.00807 | 7.50 | Yüksek | Yüksek | Eşleşti |
| V035 | libc6 2.41-12+deb13u3 - CVE-2026-5450 | 9.8 | 0.00718 | 0.01 | Düşük | Orta | Uyuşmadı |
| V036 | libc6 2.41-12+deb13u3 - CVE-2019-1010022 | 9.8 | 0.03249 | 9.80 | Yüksek | Orta | Uyuşmadı |

---

## 3. Uyuşmayan Kayıtlar ve Gerekçe Analizi

### V001 — SQL Injection - login formu (Login Admin)
- **Metrikler:** CVSS: `9.8` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `9.8`) vs. K2 Uzman: **Kritik**
- **Model v1 Gerekçesi:** SQL Injection, yüksek saldırı karmaşıklığı ve yüksek CVSS vektörü gösterilmiştir. Ancak, kimlik dogrulama ve yüksek saldırı karmaşıklığı kritik olan yerlerde, yüksek etki etkileşimini ve erişilebilirliğini doğrudan yan etkilemiş olabilir.
- **K2 Uzman Gerekçesi:** Login Admin challenge'ı ve CVSS 9.8, kimlik doğrulamasız yönetici erişimini destekliyor; uygulamaya özgü etki ve saldırı yolu açık.

### V003 — Reflected XSS - siparis takip
- **Metrikler:** CVSS: `6.1` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `6.1`) vs. K2 Uzman: **Orta**
- **Model v1 Gerekçesi:** Reflected XSS (CVE-2023-XXXX) siparis takipi gibi saldırı yolu uygulanabilir, ancak gerekli kimlik doğrulama ve yüksek saldırı karmaşıklığı yok. Bu saldırı, internet'nin yönündeki kullanıcılar için etkisini etkilemiş olsa da, kritiklik ve yüksek CVSS skoru ile yaklaşık 6.1 skorunu sağlar.
- **K2 Uzman Gerekçesi:** Reflected XSS, sipariş takibi girdisi ve kurbanın etkileşimini gerektiriyor; olası etki oturumun etkilenmesi olsa da kullanıcı tıklaması gerekli.

### V004 — DOM XSS - arama kutusu
- **Metrikler:** CVSS: `6.1` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `6.1`) vs. K2 Uzman: **Orta**
- **Model v1 Gerekçesi:** Vuln ID: V004, CVE ID: nan, İsim/Başlık: DOM XSS - arama kutusu, Bileşen (Component): search, CWE ID: CWE-79, CVSS Skoru: 6.1, CVSS Vektörü: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N, EPSS Skoru: bilinmiyor, Maruziyet (Exposure): internet, Kimlik Doğrulama (Auth Required): hayir, Saldırı Karmaşıklığı (Attack Complexity): low, Varlık Kritikliği (Asset Criticality): 3, Notlar: challenges.json: XSS; istemci tarafi, UI:R. Bu durumda, bu şekilde yönetici yetkisini etkileyecek ve saldırı yolu uygulanabilir. Bu, öncelikli bir saldırı yolu gösterilmektedir ve kritiklik yönelik etkileri olabilir.
- **K2 Uzman Gerekçesi:** DOM XSS arama kutusuyla ilişkili ve CVSS 6.1; saldırının etkisi tarayıcıdaki kullanıcıya bağlı, kullanıcı etkileşimi gerekiyor.

### V005 — API-only (Stored) XSS
- **Metrikler:** CVSS: `6.1` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `6.1`) vs. K2 Uzman: **Orta**
- **Model v1 Gerekçesi:** API-only (Stored) XSS, yüksek saldırı karmaşıklığı ve yüksek CVSS vektörü gösterilmiştir. API-only (Stored) XSS, yönetici yetkisini elde etmek için yönetici yetkisini elde etmek istenen bir yönetici etiketleme ölçümü için yüksek seviyesi düşük etkisini düşebilir.
- **K2 Uzman Gerekçesi:** API-only stored XSS API ürün özelliğine dayanıyor; CVSS 6.1 ve kullanıcı etkileşimi gerekli, ayrıca kimlik doğrulama varsayımı kaynakta kesin değil.

### V006 — IDOR - baska kullanicinin sepetini gorme (View Basket)
- **Metrikler:** CVSS: `6.5` | EPSS: `bilinmiyor` | Auth: `evet` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `6.5`) vs. K2 Uzman: **Orta**
- **Model v1 Gerekçesi:** Vuln ID: V006, CVE ID: nan, İsim/Başlık: IDOR - baska kullanicinin sepetini gorme (View Basket), Bileşen (Component): basket, CWE ID: CWE-639, CVSS Skoru: 6.5, CVSS Vektörü: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N, EPSS Skoru: bilinmiyor, Maruziyet (Exposure): internet, Kimlik Doğrulama (Auth Required): evet, Saldırı Karmaşıklığı (Attack Complexity): low, Varlık Kritikliği (Asset Criticality): 4. Bu durumda, basket, yönetici yetkisine erişim gerekir ve hassas verilerin geniş ölçekte açığa çıkması gerekir. Bu, öncelikle kimlik doğrulama ve yönetici yetkisini erişmek için kullanılabilirlik gerektiğini ve, daha sonra daha yavaş saldırı karmaşıklığının göreceği, yüksek CVSS ve kritik seviyesi gösterilmektedir.
- **K2 Uzman Gerekçesi:** Sepet IDOR'u başka kullanıcının sepet verisini açığa çıkarabilir; CVSS 6.5 olsa da giriş gerekiyor ve etki sepet kapsamıyla sınırlı.

### V007 — IDOR - baska kullanicinin sepetini degistirme (Manipulate Basket)
- **Metrikler:** CVSS: `6.5` | EPSS: `bilinmiyor` | Auth: `evet` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `6.5`) vs. K2 Uzman: **Orta**
- **Model v1 Gerekçesi:** V007, IDOR (Insecure Direct Object Reference) saldırı yolu uygulanabilir, önemli koruma engeli yok. Etki sınırlı ve yüksek saldırı karmaşıklığı, yüksek CVSS ve vektörü, yüksek risk seviyesi olduğunu gösterir.
- **K2 Uzman Gerekçesi:** Sepet IDOR'u başka kullanıcının sepetini değiştirebilir; giriş gerekiyor ve gösterilen bütünlük etkisi tekil sepetle sınırlı.

### V008 — Mass Assignment - admin kaydi (Admin Registration)
- **Metrikler:** CVSS: `9.8` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `9.8`) vs. K2 Uzman: **Kritik**
- **Model v1 Gerekçesi:** Mass Assignment vulnerability (CVE ID: nan) in the user-registration component (Başlık: Admin Registration) poses a high risk due to the lack of proper input validation, allowing for potential privilege escalation. The absence of authentication for this critical functionality, combined with the high CVSS score of 9.8, indicates that the vulnerability could be exploited with relative ease, potentially leading to unautnerable access to sensitive administrative functions. The exposure through the internet and the absence of asset criticality mitigation measures further elevate the risk level. Immediate action is required to address this vulnerability to prevent potential security breaches.
- **K2 Uzman Gerekçesi:** Admin Registration challenge'ı ayrıcalıklı admin kaydını ve CVSS 9.8'i gösteriyor; normal kayıt üzerinden kimlik doğrulamasız yönetici erişimi elde edilebilir.

### V011 — Zayif guvenlik sorusu ile sifre sifirlama (Reset Jim's Password)
- **Metrikler:** CVSS: `7.4` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `high`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `7.4`) vs. K2 Uzman: **Orta**
- **Model v1 Gerekçesi:** Vuln ID: V011, CVE ID: nan, İsim/Başlık: Zayif guvenlik sorusu ile sifre sifirlama (Reset Jim's Password), Bileşen (Component): reset-password, CWE ID: CWE-640, CVSS Skoru: 7.4, CVSS Vektörü: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N, EPSS Skoru: bilinmiyor, Maruziyet (Exposure): internet, Kimlik Doğrulama (Auth Required): hayir, Saldırı Karmaşıklığı (Attack Complexity): high, Varlık Kritikliği (Asset Criticality): 5, Notlar: challenges.json: Broken Authentication; OSINT gerektirir (AC:H). Bu durum, yönetici yetkisini elde etmek için yönetici yetkisini elde etmek, sistemin bütünde açıklanması ve hassas verilerin geniş ölçekte açığa çıkması gerekir.
- **K2 Uzman Gerekçesi:** Şifre sıfırlama Jim hesabıyla sınırlı ve envanter yüksek karmaşıklık/OSINT gereksinimi belirtiyor; etki ciddi olsa da hedef ve önkoşul sınırlı.

### V012 — CSRF - profil islemi
- **Metrikler:** CVSS: `4.3` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `4.3`) vs. K2 Uzman: **Düşük**
- **Model v1 Gerekçesi:** Vuln ID: V012, CVE ID: nan, İsim/Başlık: CSRF - profil islemi, Bileşen (Component): profile, CWE ID: CWE-352, CVSS Skoru: 4.3, CVSS Vektörü: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N, EPSS Skoru: bilinmiyor, Maruziyet (Exposure): internet, Kimlik Doğrulama (Auth Required): hayir, Saldırı Karmaşıklığı (Attack Complexity): low, Varlık Kritikliği (Asset Criticality): 3, Notlar: challenges.json: Broken Access Control. Bu durumda, profil islemi CSRF gibi yöntemlerle yönelik çıkması gerekir. Profil islemleri, kullanıcının yöneticinin yönetilebilirlikle yapılandırılmasına yönelik yönetim yapılarını kullanarak, kullanıcının yönetilebilirlikle yönetilemezliğini sağlamak için gerekli olan kimlik doğrulama, yüksek saldırı karmaşıklığı ve kullanıcı etkileşimi gibi yönelik gerekçeleri gerektiğini belirleyebilir. Bu durumda, yönetici yetkisini elde etmek, sistemin bütünlemeye yönelik yönetilmesi ve hassas verilerin geniş ölçekte açığa çıkması gibi yönelik saldırılar yönelik olarak gerekmeyeceğine karar verilmiyor.
- **K2 Uzman Gerekçesi:** CSRF ile profil adının değiştirilmesi için kurban etkileşimi gerekir; CVSS 4.3 ve gösterilen bütünlük etkisi sınırlı.

### V013 — Acik yonlendirme - eski allowlist (Outdated Allowlist)
- **Metrikler:** CVSS: `6.1` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `6.1`) vs. K2 Uzman: **Orta**
- **Model v1 Gerekçesi:** Acik yonlendirme - eski allowlist (Outdated Allowlist) çözümünün kritikliği, internet açıklaması ve yüksek saldırı karmaşıklığından emin olduklarında, varlık kritikliği 2 ve yüksek CVSS vektörü, yüksek etki sınırlarından emin olduklarında, sistemin yüksek zafiyet etmek ve engellemek gerekir.
- **K2 Uzman Gerekçesi:** Outdated Allowlist challenge'ı kullanıcıyı eski kripto para adresine yönlendirebildiğini gösteriyor; kullanıcı etkileşimi ve sınırlı kapsam nedeniyle etki orta düzeyde.

### V014 — Acikta kalan kimlik bilgileri (Exposed Credentials)
- **Metrikler:** CVSS: `7.5` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **ATLANDI (HTTP 500)** (Skor: `Yok (Atlandı)`) vs. K2 Uzman: **Orta**
- **Model v1 Gerekçesi:** Model 3 deneme sonunda HTTP 500 hatası nedeniyle yanıt üretemedi.
- **K2 Uzman Gerekçesi:** İstemciye gömülü geçerli test hesabı kimlik bilgileri açığa çıkıyor; hesap kimliği ve admin olup olmadığı doğrulanmadığından yönetici etkisi varsayılamaz.

### V016 — Ayrintili hata mesaji (Error Handling)
- **Metrikler:** CVSS: `5.3` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `5.3`) vs. K2 Uzman: **Düşük**
- **Model v1 Gerekçesi:** Ayrintili hata mesaji (Error Handling) kayıtında yönetici yetkisini elde ettiğinde, sistemin bütünüyle ele geçirilmesi veya hassas verilerin geniş ölçekte açığa çıkması gerekir. Bu yöntemde, yönetici yetkisini elde ettiğinde, hedeflerdeki gizli yöntemleri kullanılabilir. Bu yöntem, önemli koruma engeli yoktur ve saldırı yolu uygulanabilir. CVSS ve CVSS vektörü ile yaptığımız risk seviyesi, bu yöntemin yüksek seviyesi olduğunu belirleyebilir.
- **K2 Uzman Gerekçesi:** Hata işleme bulgusu CVSS 5.3 ve düşük varlık kritikliği taşıyor; kayıtta sınırlı bilgi ifşası dışında somut etki gösterilmiyor.

### V017 — CSP basligi yok
- **Metrikler:** CVSS: `4.2` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `high`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `4.2`) vs. K2 Uzman: **Düşük**
- **Model v1 Gerekçesi:** CSP basligi yok, çünkü bu yöntemin yönetimde bağımsızlık ve yönetici yetkisini sadece gösterilmez. Bu durum, internet'ye bağlı şiddetler ve saldırı karmaşıklığını yükseklemektedir. Kimlik doğrulama ve yüksek saldırı karmaşıklığı, yönetici yetkisini yönetmek için önemli olan gereksinimlerdir. Bu yöntem, bu gereksinimlerle ilgilidir ve bu yöntemin yöneticisi, bu güvenlik ve zafiyet için önceliklidir.
- **K2 Uzman Gerekçesi:** CSP başlığı ZAP tarafından Medium raporlanmış ancak CVSS vektörü resmi değil ve tahmini; tek başına doğrudan sömürü etkisi kanıtlanmamış.

### V018 — Cross-Domain Misconfiguration (genis CORS)
- **Metrikler:** CVSS: `3.1` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `high`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `3.1`) vs. K2 Uzman: **Düşük**
- **Model v1 Gerekçesi:** Cross-Domain Misconfiguration (genis CORS) açısaldırma, internet etkinleştirildi ve saldırı karmaşıklığı yüksek olan şekilde, yüksek CVSS ve kritik seviyesi yaklaşık 8.5 olarak belirtilmiştir. Kimlik doğrulama hayır olduğunu ve yüksek saldırı karmaşıklığı ve kullanıcı etkileşimi gerektiğini belirleyen, bu nedenle yüksek risk seviyesi olduğundan emin değildir.
- **K2 Uzman Gerekçesi:** CORS bulgusunda CVSS 3.1 tahmini, yüksek karmaşıklık ve düşük varlık kritikliği var; rapor tek başına hassas veriye erişimi doğrulamıyor.

### V019 — Server basliginda surum bilgisi sizintisi
- **Metrikler:** CVSS: `5.3` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `5.3`) vs. K2 Uzman: **Düşük**
- **Model v1 Gerekçesi:** Server basliginda surum bilgisi sizintisi, internet bağlı olmasından, saldırı karmaşıklığında yüksek, ancak kritiklik ve yüksek CVSS vektörü gibi özelliklerle yüksek risk seviyesi olduğunu düşünülebilir.
- **K2 Uzman Gerekçesi:** Sunucu sürüm bilgisinin sızması keşfe yardımcı olabilir; ZAP Low bulgusu ve varlık kritikliği 1, doğrudan etki gösterilmiyor.

### V020 — Tehlikeli JS fonksiyonlari
- **Metrikler:** CVSS: `4.2` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `high`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `4.2`) vs. K2 Uzman: **Düşük**
- **Model v1 Gerekçesi:** Tehlikeli JS fonksiyonlari, frontend component'nin yönetiminde kritik etkiye dayanır. CVSS Skoru 4.2, CVSS Vektörü Yüksek ve Yüksek CVSS Skorunu ile Yüksek etki seviyesi döndürülmüştür. Kimlik Doğrulama ve Saldırı Karmaşıklığı YAPMA, önkoşullar ve etkileşim gereklidir. Asset Criticality 2, bu saldırıların etkisi yüksek olduğundan emin değildir.
- **K2 Uzman Gerekçesi:** Tehlikeli JavaScript fonksiyonu bulgusunda sömürülebilirlik belirsiz ve ZAP Low; bağımsız bir saldırı etkisi kanıtlanmamış.

### V021 — COOP/COEP basliklari eksik
- **Metrikler:** CVSS: `3.1` | EPSS: `bilinmiyor` | Auth: `hayir` | Karmaşıklık: `high`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `3.1`) vs. K2 Uzman: **Düşük**
- **Model v1 Gerekçesi:** Vuln ID: V021, CVE ID: nan, İsim/Başlık: COOP/COEP basliklari eksik, Bileşen (Component): http-headers, CWE ID: CWE-693, CVSS Skoru: 3.1, CVSS Vektörü: CVSS:3table:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N, EPSS Skoru: bilinmiyor, Maruziyet (Exposure): internet, Kimlik Doğrulama (Auth Required): hayir, Saldırı Karmaşıklığı (Attack Complexity): high, Varlık Kritikliği (Asset Criticality): 1, Notlar: zap_baseline.json: Low; iki ZAP bulgusu birlestirildi. Bu durum, çünkü varlık kritikliği 1 ve saldırı karmaşıklığı high, yüksek CVSS ve kritik etkinlikleri ve yüksek saldırı karmaşıklığı, yüksek risk seviyesi döndürülmüştür.
- **K2 Uzman Gerekçesi:** COEP/COOP başlık eksikliği ZAP Low olarak raporlanmış; birleştirilmiş savunma başlığı bulgusu doğrudan veri veya hesap etkisi göstermiyor.

### V022 — jsonwebtoken 0.1.0 / 0.4.0 - CVE-2015-9235
- **Metrikler:** CVSS: `9.8` | EPSS: `0.08524` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Kritik** (Skor: `9.8`) vs. K2 Uzman: **Yüksek**
- **Model v1 Gerekçesi:** jsonwebtoken 0 endeki 0.1.0 ve 0.4.0 saldırılarını etkinleştirmek için kullanılabilir bir kimlik dogrulama süreçi olan CVE-2015-9235. Bu saldırı, kimlik dogrulama süresi ve yüksek saldırı karmaşıklığını etkileyen bir yöntemdir. Bu yöntem, yönetici yetkisini elde etmek için yönetici yetkisini elde ettiğinde sistemin bütünleşmesi ve yüksek saldırı yolu uygulanabilir. Bu yöntem, kritik seviyede etkinleştirilmiştir ve çoklu saldırılıklarının yüksek olduğu gösterilmiştir.
- **K2 Uzman Gerekçesi:** Trivy CRITICAL JWT algoritma karışıklığı ve kimlik doğrulama atlatma bildiriyor; ancak bağımlılık kaydı zafiyetli kod yolunun uygulamada erişilebilir olduğunu tek başına doğrulamıyor.

### V023 — lodash 2.4.2 - CVE-2019-10744
- **Metrikler:** CVSS: `9.1` | EPSS: `0.05006` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Kritik** (Skor: `9.1`) vs. K2 Uzman: **Yüksek**
- **Model v1 Gerekçesi:** V023 CVE-2019-10744, lodash 2.4.2'nin yerine yeniden yapılandırılması ve yönetici yetkisini elde etmek için kullanılabilirlik ve yönetici yetkisini elde etmek için yüksek CVSS vektörü ve skoru, kritik seviyeyi sağlar. İşlev, internet'nda yansıtılan, varlık kritikliği 3'ye sahip, saldırı karmaşıklığında yüksek, ancak gerekli kimlik doğrulama ve yüksek saldırı karmaşıklığının yok olduğu gibi, yüksek CVSS vektörü ve skoru ile kritik seviyeyi sağlamak için gereklidir.
- **K2 Uzman Gerekçesi:** Trivy CRITICAL prototype pollution için CVSS 9.1 ve bütünlük/kullanılabilirlik etkisi bildiriyor; paket taraması tek başına uygulamadaki sömürü yolunu kanıtlamıyor.

### V025 — crypto-js 3.3.0 - CVE-2023-46233
- **Metrikler:** CVSS: `9.1` | EPSS: `0.00635` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Kritik** (Skor: `9.1`) vs. K2 Uzman: **Yüksek**
- **Model v1 Gerekçesi:** Crypto-js 3.3 endeki CVE-2023-46233, yönetici yetkisi elde edilebilir ve sistemin bütünüyle ele geçirilmesi veya hassas verilerin geniş ölçekte açığa çıkması gerekir. Bu yöntem, yüksek CVSS ve kritik seviyeli saldırı yolu uygulanabilir.
- **K2 Uzman Gerekçesi:** Zayıf PBKDF2 parola hash'lerini etkileyebilir; CVSS 9.1 olsa da yetkinlik sözlüğü hash'lerin önceden elde edilmesini gerektiriyor ve paket yolu doğrulanmış değil.

### V027 — decompress 4.2.1 - CVE-2026-101894
- **Metrikler:** CVSS: `9.1` | EPSS: `0.00814` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Kritik** (Skor: `9.1`) vs. K2 Uzman: **Yüksek**
- **Model v1 Gerekçesi:** V027 CVE-2026-1 end of the document:  {
- **K2 Uzman Gerekçesi:** Path traversal için Trivy CRITICAL ve CVSS 9.1 bildiriyor; paket bulgusu ağır potansiyel etki taşısa da uygulamada erişilebilirlik ayrıca doğrulanmalı.

### V035 — libc6 2.41-12+deb13u3 - CVE-2026-5450
- **Metrikler:** CVSS: `9.8` | EPSS: `0.00718` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Düşük** (Skor: `0.00718`) vs. K2 Uzman: **Orta**
- **Model v1 Gerekçesi:** CVSS ve Trivy sayısal değerleri ile yaptığı gösterilmiş bir risk yaklaşımı, bu sayede saldırı karmaşıklığından emin olmak için yüksek saldırı karmaşıklığı ve yüksek CVSS değerleri gösterilmiştir. Bu nedenle, bu risk yaklaşımı yaklaşımda ortaya çıkması gerekir.
- **K2 Uzman Gerekçesi:** CVSS 9.8 ciddi potansiyel etki gösterse de Trivy önem derecesi MEDIUM, EPSS 0.00718 ve tarama kanıtı çelişkili; sömürü yolu da doğrulanmış değil.

### V036 — libc6 2.41-12+deb13u3 - CVE-2019-1010022
- **Metrikler:** CVSS: `9.8` | EPSS: `0.03249` | Auth: `hayir` | Karmaşıklık: `low`
- **Karşılaştırma:** Model v1: **Yüksek** (Skor: `9.8`) vs. K2 Uzman: **Orta**
- **Model v1 Gerekçesi:** Vuln ID: V036, CVE ID: CVE-2019-1 end of the instruction as requested. Here is the continuation and completion of the JSON output with the risk score, label, and reasoning based on the provided CVSS and Uzman Etiketleme Ölçütu kuralları: 9.8, Yüksek,
- **K2 Uzman Gerekçesi:** CVSS 9.8 ile Trivy LOW derecesi çelişiyor; EPSS 0.03249 olsa da libc6 bulgusunda gerçek uygulama yolu ve etki envanter kaynaklarıyla doğrulanmamış.

---

## 4. Tespit Edilen Ortak Hata Kalıpları

1. **CVSS Skorunu Birebir Kopyalama (Anchoring Bias):**
   - İşlenen 35 kaydın **34 tanesinde** (`%97.1`) `risk_score_llm` değeri, girdi olarak verilen `cvss_score` ile birebir aynı üretilmiştir.
2. **Aynı Skoru Çok Sayıda Kayda Verme (Skor Kümelenmesi):**
   - Model bağlamsal farkları sayısal skora yansıtamadığı için aynı puanları tekrarlamıştır. Birden fazla kez verilen skorlar: `{7.5: 6, 9.8: 4, 6.1: 4, 9.1: 4, 6.5: 3, 5.3: 2, 4.2: 2, 3.1: 2}`.
3. **Sınıf Dengesizliği ve 'Yüksek' Etiketine Yığılma:**
   - **Model v1 Dağılımı:** `{'Yüksek': 30, 'Kritik': 4, 'Düşük': 1}`
   - **K2 Uzman Dağılımı:** `{'Yüksek': 17, 'Orta': 10, 'Düşük': 7, 'Kritik': 2}`
   - Model, K2'nin `Orta` (9 kayıt) ve `Düşük` (6 kayıt) olarak ayırdığı bulguların tamamına yakınını `Yüksek` sınıfına yığmıştır.
4. **EPSS ve Önkoşul (Kimlik Doğrulama / Kullanıcı Etkileşimi) Sinyallerini Yok Sayma:**
   - Çok düşük EPSS değerine ve yüksek önkoşullara sahip bulgularda bile (ör. `V017`, `V018`, `V021` gibi düşük CVSS/EPSS'li yapılandırma bulguları) model `Yüksek` kararı vermiştir.
   - `V035` kaydında ise model CVSS (`9.8`) yerine yanlışlıkla EPSS skorunu (`0.00718`) `risk_score_llm` olarak atayıp kaydı `Düşük` etiketlemiştir.
5. **Bağımlılık (Trivy) ve Uygulama Kanıtı Ayrımında Terslik:**
   - Model, uygulama içi kesin yönetici erişimi kanıtı olan `V001` ve `V008` kayıtlarını `Yüksek` seviyesinde bırakırken; kod yolu erişilebilirliği belirsiz olan Trivy bağımlılık bulgularını (`V022`, `V023`, `V025`, `V027`) `Kritik` olarak etiketlemiştir.

---

## 5. Tutarlılık Testi (Aynı Kaydın 3 Kez Çalıştırılması)

`temperature=0.1` ayarında seçilen 5 temsili kaydın art arda 3 kez çalıştırılmasıyla elde edilen skor ve etiket değişimleri:

| Vuln ID | Girdi CVSS | 1. Çalıştırma | 2. Çalıştırma | 3. Çalıştırma | Maks. Skor Farkı | Std. Sapma | Etiket Tutarlı mı? |
|---|---:|---|---|---|---:|---:|---|
| V001 | 9.8 | 9.8 (Kritik) | 9.8 (Yüksek) | 9.8 (Yüksek) | 0.0 | 0.0 | Hayır |
| V003 | 6.1 | 6.1 (Yüksek) | 6.1 (Yüksek) | 6.1 (Yüksek) | 0.0 | 0.0 | Evet |
| V018 | 3.1 | 3.1 (Yüksek) | 3.1 (Yüksek) | 3.1 (Yüksek) | 0.0 | 0.0 | Evet |
| V022 | 9.8 | 9.8 (Kritik) | 9.8 (Kritik) | 9.8 (Kritik) | 0.0 | 0.0 | Evet |
| V035 | 9.8 | 9.8 (Kritik) | 9.8 (Kritik) | 9.8 (Kritik) | 0.0 | 0.0 | Evet |


## Tutarlılık Testi Çıktısının Yorumu

1- Sayısal Skorlarda Sıfır Sapma (Fark=0.0), Ancak CVSS Çapalaması: Her 5 kayıtta da 3 çalıştırmanın tamamında sayısal skor milimi milimine aynı (9.8, 6.1, 3.1) çıkmış. Bunun sebebi temperature=0.1 ayarının yanı sıra modelin doğrudan girdi cvss_score değerini kopyalamasıdır (V035 için bile bu kez CVSS 9.8 değerini kopyalamış).

2- Sayısal Skor ile Etiket Arasındaki Kopukluk (V001): V001 kaydında 3 çalıştırmada da skor 9.8 olmasına rağmen ilkinde Kritik, diğer ikisinde Yüksek etiketi üretilmiş. Bu da modelin sayısal skoru ayrı, kategorik etiketi ayrı değerlendirdiğini gösteriyor.

3- Çalıştırmalar Arası Anomali (V035): Ana CSV üretiminde V035 için 0.00718 (Düşük) üreten model, bu 3 tekrarda 9.8 (Kritik) üretmiş.