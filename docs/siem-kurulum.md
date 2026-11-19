# Merkezi log ve alarm panosu (S5-K5, S6-K5)

**Tarih:** 18.11.2026
**Araçlar:** Grafana 11.5.2 (pano), Loki 3.4.2 (log veritabanı), Alloy 1.7.1 (log toplayıcı)
**Başlatma:** `docker compose --profile siem up -d` · Pano: `http://localhost:3001` (`admin` / `Admin-Lab-2026!`, yalnızca lab)

---

## 1. Araç seçimi

Planda "Wazuh veya Elastic" yazıyordu. **Grafana + Loki + Alloy** seçildi.

| | Grafana + Loki + Alloy | Wazuh (tek düğüm) | Elastic (ES + Kibana) |
|---|---|---|---|
| Yaklaşık RAM | ~0.5 GB | 6–8 GB | 3–4 GB |
| Kurulum | Tek compose, 3 yapılandırma dosyası | Sertifika üretimi, çekirdek ayarı, ajan | Orta |
| ModSecurity JSON logu | Doğrudan | Ek kod çözücü gerekiyor | Ek ayar gerekiyor |
| Hazır saldırı kuralları, MITRE eşlemesi, korelasyon | Yok | Var | Kısmen |
| Tekrar üretilebilirlik (S8) | Pano bir JSON dosyası, otomatik yükleniyor | Zor | Orta |

**Gerekçe:**
- Lab'daki bütün trafik tek kaynaktan geliyor (Docker host geçidi, `172.30.1.1`). Farklı kaynaklardaki olayları ortak bir IP üzerinden birleştiren **korelasyon kuralları bu ortamda yeni bilgi üretmez**.
- Artık risk hesabında SIEM/IDS "tespit eder" (etkinlik 0.2) olarak giriyor (`docs/olcum-metodolojisi.md`); bu değer kullanılan araçtan bağımsız.
- En önemli kaynak olan ModSecurity JSON logu için Wazuh'ta hazır kural yok; kurallar zaten elle yazılacaktı.
- **MITRE ATT&CK eşlemesi elle yapıldı** (Bölüm 4): her eşlemenin gerekçesi görünür.

**Adlandırma:** Bu kurulum tam bir SIEM değil; raporda **"merkezi log ve alarm panosu"** olarak adlandırılır.

## 2. Mimari

```
defense/logs/modsecurity/audit.log ─┐
defense/logs/nginx/access.log ──────┤
defense/suricata/logs/eve.json ─────┼──> Alloy ──> Loki ──> Grafana (:3001)
oauth2-proxy, keycloak (stdout) ────┘   (etiket,     (depo)   (pano)
                                         ATT&CK)
```

- Üç servis ayrı bir `siem` ağında; WAF, Juice Shop ve Suricata ağlarına bağlı değiller. Alloy logları **dosyadan** (salt okunur bağlama) ve Docker'ın kendi log akışından okuyor; lab trafiğine hiç girmiyor.
- `siem` profili: `docker compose up -d` bu servisleri başlatmaz; yalnızca `--profile siem` ile başlar. Pano gerekmediğinde lab hafif kalır.
- Alloy yalnızca **yeni** satırları okur (`tail_from_end`): pano kurulumdan sonraki olayları gösterir.

## 3. Toplanan kaynaklar ve etiketler

| Kaynak | `job` | Etiketler | Not |
|---|---|---|---|
| ModSecurity audit log (JSON) | `modsecurity` | `status` (yanıt kodu), `teknik` (ATT&CK) | Bölüm 4 |
| nginx access log | `nginx` | — | Ham satır |
| Suricata `eve.json` | `suricata` | `event_type`, `in_iface`, `bacak` | `stats` kayıtları atılıyor; `bacak` **IP adresinden**: 172.30.1.x = `istemci-waf`, 172.30.2.x = `waf-juiceshop`. Arayüz adı (eth0/eth1) kullanılmıyor, çünkü WAF yeniden oluşturulunca yer değiştirebiliyor (Bölüm 8) |
| oauth2-proxy, Keycloak | `iam` | `container` | Docker log akışından |

## 4. MITRE ATT&CK eşlemesi

ModSecurity kaydında tetiklenen CRS kural ailesine göre atanıyor (`siem/config.alloy`, `loki.process "modsecurity"`). Bir istekte birden fazla aile varsa yapılandırmadaki sıraya göre **son** eşleşen etiket kalır. Sıra: 913, 932, 930/931, 934, 941, 942, 911, 10100. Path traversal hem 930 hem 932160'ı tetiklediği için 930/931 932'den sonra geliyor; ilk sürümde bu sıra tersti ve path traversal "Komut" olarak etiketleniyordu.

| CRS kuralları | Saldırı sınıfı | ATT&CK tekniği | Panodaki etiket | Gerekçe |
|---|---|---|---|---|
| 913xxx | Tarayıcı / otomatik araç | T1595 Active Scanning | Tarama · T1595 | `sqlmap` gibi araçların keşif taraması |
| 930xxx, 931xxx | Path traversal / dosya dahil etme | T1083 File and Directory Discovery | Dosya keşfi · T1083 | Sunucudaki dosyaları okuma girişimi |
| 932xxx | Komut enjeksiyonu | T1059 Command and Scripting Interpreter | Komut · T1059 | Sunucuda komut çalıştırma girişimi |
| 934xxx | SSRF | T1190 Exploit Public-Facing Application | SSRF · T1190 | Uygulamayı iç adreslere istek attırma |
| 941xxx | XSS | T1189 Drive-by Compromise | XSS · T1189 | Kurbanın tarayıcısında kod çalıştırma |
| 942xxx | SQL enjeksiyonu | T1190 Exploit Public-Facing Application | SQLi · T1190 | Herkese açık uygulamadaki açığı sömürme |
| 911100 | İzin verilmeyen HTTP metodu | T1190 | Metod · T1190 | Metod politikasını aşma girişimi |
| 10100 (SY-1) | V003 sanal yaması | T1190 | SY-1 (V003) · T1190 | Sipariş takibindeki enjeksiyon |

**Sınırlılık:** Eşleme kural ailesi düzeyinde; tek tek isteğin niyetini değil, tetiklenen kuralın sınıfını yansıtıyor. Örneğin XSS hem T1189 hem T1190 olarak düşünülebilir; burada kurbanın tarayıcısını hedeflediği için T1189 seçildi.

## 5. Pano: "ResidualMap lab: savunma olayları"

| Panel | Ne gösteriyor |
|---|---|
| WAF: engellenen istek (403) | Seçili zaman aralığındaki toplam engelleme |
| Suricata: alarm | İki bacaktaki toplam alarm |
| IAM: başarısız giriş / yetkisiz | oauth2-proxy `AuthFailure` (rol yok) + Keycloak `LOGIN_ERROR` (yanlış şifre) |
| IAM: başarılı giriş | oauth2-proxy `AuthSuccess` |
| Engellenen istekler, ATT&CK tekniğine göre | Zaman içinde, tekniğe göre yığılmış çubuklar |
| Tekniklere göre toplam | Aynı veri, toplam |
| Suricata: bacağa göre HTTP trafiği ve alarm | İki bacaktaki HTTP ve alarm sayısı; WAF'ın engellediği saldırılar Juice Shop bacağına ulaşmıyor |
| Suricata alarmları | Alarm imzası, bacak, kaynak ve hedef |
| WAF: son engellenen istekler | İlk tetiklenen kural, yöntem, adres, teknik |
| IAM olayları | oauth2-proxy ve Keycloak giriş satırları |

Pano dosyası: `siem/grafana/dashboards/residualmap-lab.json`. Grafana açılışta otomatik yüklüyor: **Dashboards → ResidualMap → "ResidualMap lab: savunma olayları"**.

## 6. Doğrulama (18.11.2026, `test-waf.sh` + `test-iam.py`, son 5 dakika)

| Kontrol | Beklenen | Sonuç |
|---|---|---|
| Altı servis (lab + `siem` profili) ayakta | Hepsi "Up" | ✓ |
| Grafana açılıyor, Loki veri kaynağı bağlı, pano yüklü | Dashboards → ResidualMap | ✓ |
| WAF: engellenen istek | 10 (`test-waf.sh`'tan 8 + `test-iam.py`'dan 2 I-4 sınır testi) | **10** ✓ |
| Teknik dağılımı | SQLi 2, XSS 2, SY-1 2, SSRF 2, Dosya keşfi 1, Tarama 1 | ✓ (toplam 10) |
| `misafir`'in rol 403'ü WAF engellemesi sayılmıyor | Sayılmamalı | ✓ (yalnızca 949110 / 10100 kuralı olan kayıtlar sayılıyor) |
| Suricata alarm | 4, hepsi `istemci-waf` bacağında | **4**, hepsi `istemci-waf` (172.30.1.1 → 172.30.1.10) ✓ |
| Suricata HTTP, bacağa göre | İki bacakta da kayıt | `istemci-waf` 60, `waf-juiceshop` 8 ✓ |
| IAM başarılı / başarısız | 1 / 1 | **1 / 1** (`personel` AuthSuccess, `misafir` AuthFailure) ✓ |
| Olayların panoya düşme süresi | — | 10–20 saniye (pano 10 sn'de bir yenileniyor) |

**Bacak sayılarının yorumu:** `istemci-waf` bacağı yalnızca istemci isteklerini değil, WAF'ın oauth2-proxy'ye sorduğu kimlik kontrollerini de görüyor (ikisi de `frontend` ağında). Girişsiz `/ftp` istekleri de Keycloak'a yönlendirildiği için Juice Shop'a hiç gitmiyor. Bu yüzden 60 − 8 = 52 "engellenen istek" değildir; engellenen istek sayısı WAF panelinden (ModSecurity) okunur. Bu panelin asıl gösterdiği: **alarm üreten saldırıların hiçbiri Juice Shop bacağına ulaşmadı.**

**Kurulum sırasında düzeltilenler:**

| Sorun | Neden | Çözüm |
|---|---|---|
| "Dashboard failed to load" (ana sayfa) | Ana sayfa ayarı panoyu dosyadan ikinci kez okumaya çalışıyordu | Ayar kaldırıldı; pano Dashboards → ResidualMap altında |
| WAF 403 sayısı bir fazla | `misafir`'in oauth2-proxy 403'ü de yanıt kodu 403 olarak sayılıyordu | Yalnızca engelleme kuralı (949110 / 10100) olan kayıtlar sayılıyor |
| Path traversal "Komut" olarak etiketleniyordu | İstek hem 930 hem 932160'ı tetikliyor; son eşleşen kazanıyor | 930/931, 932'den sonraya alındı |
| Alarmlar `waf-juiceshop` bacağında görünüyordu | WAF yeniden oluşturulunca `eth0`/`eth1` yer değiştirdi; bacak arayüz adına bağlıydı | Bacak IP adresinden belirleniyor |
| Çubuk göstergelerde "Value A / Value B" | Anlık sorgularda ad şablonu uygulanmıyor | Aralık sorgusu + son değer |
| Teknik adları kesiliyordu | Uzun ATT&CK adları | Kısa etiket: "SQLi · T1190" biçimi |

Panonun son hali: `docs/img/siem-pano.png`.

## 7. Kaynak kullanımı (18.11.2026, `docker stats --no-stream`, boşta)

| Container | RAM | CPU |
|---|---|---|
| loki | 105.3 MiB | %0.72 |
| alloy | 42.8 MiB | %0.76 |
| grafana | 93.9 MiB | %1.51 |
| **Toplam** | **~242 MiB** | **~%3** |

Karşılaştırma: Wazuh tek düğüm kurulumu için önerilen bellek 6–8 GB, yani bu kurulumun yaklaşık 25–30 katı (Bölüm 1).

## 8. Sınırlılıklar

- Tam bir SIEM değil: hazır saldırı kuralları ve olay korelasyonu yok (gerekçe Bölüm 1).
- ATT&CK eşlemesi kural ailesi düzeyinde ve elle yapıldı (Bölüm 4).
- Loglar 14 gün tutuluyor; lab dışında bir saklama politikası tanımlanmadı.
- Grafana yönetici şifresi compose dosyasında açık (yalnızca lab).
- **Arayüz adları sabit değil.** 18.11.2026'da WAF yeniden oluşturulduktan sonra Docker ağları farklı sırayla bağladı ve `eth0`/`eth1` yer değiştirdi; ilk sürümde bacak etiketi arayüz adına bağlı olduğu için alarmlar yanlış bacakta göründü. Bacak artık IP adresinden belirleniyor; IP'ler compose'da sabit.

  | Zaman | `eth0` | `eth1` |
  |---|---|---|
  | 18.11.2026 sabah (segmentasyon sonrası) | 172.30.1.10 (frontend) | 172.30.2.10 (backend) |
  | 18.11.2026 akşam (I-4 için WAF yeniden oluşturulduktan sonra) | **172.30.2.10 (backend)** | **172.30.1.10 (frontend)** |

  Kaynak: `docker exec lab-suricata ip -4 -br addr`.
- Alloy'un Docker soketine salt okunur erişimi var (oauth2-proxy ve Keycloak loglarını okumak için). Gerçek bir dağıtımda bu, bir log sürücüsüyle değiştirilir.
