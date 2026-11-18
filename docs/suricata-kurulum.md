# Suricata IDS Kurulumu (Juice Shop trafiği)

**Amaç:** IDS'in Juice Shop trafiğinde alarm ürettiğini göstermek.

## Mimari

Suricata, nginx/WAF konteynerinin ağ alanına (`network_mode: "service:waf"`) bağlanan bir sidecar'dır ve onun `eth0` arayüzünü dinler. Docker Desktop'ta (Windows) host ağı bir VM'de olduğu için `network_mode: host` lab trafiğini görmez; sidecar yaklaşımı bu yüzden seçildi.

```
tarayıcı/curl ──> [ waf (nginx) ] ──> [ juice-shop ]
                     ▲ aynı netns
                  [ suricata ] ──> defense/suricata/logs/eve.json
```

Suricata aynı isteği iki kez görür: istemci → nginx (8080) ve nginx → juice-shop (3000). Bu yüzden alarmların çoğu 2 kez kaydedilir.

## Dosyalar

| Dosya | Görevi |
|---|---|
| `defense/docker-compose.yml` (`suricata` servisi) | Suricata servisi |
| `defense/suricata/suricata.yaml` | Yapılandırma (HOME_NET, eve.json, kural dosyaları) |
| `defense/suricata/rules/local.rules` | Lab için 4 yerel kural (sid 9000001-9000004) |
| `defense/suricata/disable.conf` | Gürültülü/ilgisiz kuralları kapatma listesi |
| `defense/suricata/threshold.config` | Alarm sınırlama/bastırma |
| `defense/suricata/lib/` | İndirilen ET Open kuralları (git'e eklenmez) |
| `defense/suricata/logs/` | `eve.json` (git'e eklenmez) |

`.gitignore` önerisi: `defense/suricata/lib/*`, `defense/suricata/logs/*` (`.gitkeep` hariç).

> Not: `suricata` servisindeki `network_mode: "service:waf"` satırındaki `waf`, nginx/WAF servisinin adıyla aynı olmalı.

## Adımlar (PowerShell, `defense/` klasöründen)

**1. Emerging Threats Open kurallarını indir**

```powershell
docker compose run --rm --entrypoint suricata-update suricata
```

Sonunda `Loaded N rules` ve `Done` benzeri çıktı görmelisin. Kurallar `defense/suricata/lib/rules/suricata.rules` altına yazılır. Sondaki `Reload command failed ... socket` uyarısı zararsızdır (geçici konteyner çalışan Suricata'ya ulaşamaz); bu yüzden adım 2'de yeniden başlatılır.

**2. Suricata'yı başlat / yeniden başlat**

```powershell
docker compose up -d suricata          # ilk kez veya compose değiştiyse
docker compose restart suricata        # sadece kurallar değiştiyse
docker ps --format "table {{.Names}}\t{{.Status}}"
docker compose logs suricata --tail 30
```

`lab-suricata` için `Up ...` görülmeli ve logda `Engine started.` olmalı. `restart` komutu ekranda `0/1 Restarting` olarak takılı kalabilir; `Ctrl+C` ile çıkıp `docker ps` ile kontrol etmek yeterlidir.

**3. Normal trafik üret ve eve.json'u kontrol et**

```powershell
$bas = (Get-Content suricata\logs\eve.json).Count
1..20 | ForEach-Object { curl.exe -s -o NUL "http://localhost:8080/"; curl.exe -s -o NUL "http://localhost:8080/rest/products/search?q=apple" }

# olay türleri (http görünmeli)
Get-Content suricata\logs\eve.json | Select-Object -Skip $bas | ForEach-Object { ($_ | ConvertFrom-Json).event_type } | Group-Object | Format-Table Count, Name -AutoSize
```

Giriş noktası WAF'tır: `http://localhost:8080`. Bu aşamada çıkan her `alert`, normal trafikte yanlış pozitif demektir. Gürültü adayıdır (adım 6).

**4. Saldırı trafiği üret (`test-waf.sh`)**

Git Bash'te, repo kökünden (`ResidualMap/`):

```bash
BAS2=$(wc -l < defense/suricata/logs/eve.json)
bash defense/test-waf.sh
```

**5. Alarmları doğrula**

Git Bash (sadece testten sonraki alarmlar, imzaya göre sayım):

```bash
tail -n +$((BAS2+1)) defense/suricata/logs/eve.json | grep '"event_type":"alert"' \
  | grep -o '"signature_id":[0-9]*,"rev":[0-9]*,"signature":"[^"]*"' | sort | uniq -c | sort -rn
```

PowerShell alternatifi (`defense/` içinden, son 20 alarm):

```powershell
Get-Content suricata\logs\eve.json | Select-String '"event_type":"alert"' | ForEach-Object { $_.Line | ConvertFrom-Json } |
  Select-Object timestamp, src_ip, dest_ip, @{n='sid';e={$_.alert.signature_id}}, @{n='imza';e={$_.alert.signature}} -Last 20
```

Hızlı kanıt: `sid` 9000001-9000004 satırları local kurallardan, diğerleri ET Open'dan gelir.

**6. Gürültülü kuralları not et**

Karar kuralı:
- Normal trafikte (adım 3) alarm veren kural: **gürültü**. `disable.conf`'a ekle veya `threshold.config` ile sınırla.
- Sadece `test-waf.sh` sırasında alarm veren kural: **işe yarar**, kalsın.
- Her `disable.conf` değişikliğinden sonra adım 1'i tekrarla ve `docker compose restart suricata` çalıştır.

## Test sonuçları (16.11.2026)

**Ortam:** Suricata 8.0.7 (`jasonish/suricata`), `waf` konteynerine sidecar, `eth0` dinleniyor.
**Kural seti:** ET Open, 69.466 kural yüklendi, 53.508'i aktif; dnp3/modbus grupları kapatıldı (16 kural).

### Normal trafik (adım 3)

40 istek → 80 `http` olayı, 2 `alert` (ikisi de `2002825 ET INFO POSSIBLE Web Crawl using Curl`).

### Saldırı trafiği (test-waf.sh)

| Test | HTTP | SID | İmza | Adet | Kaynak |
|---|---|---|---|---|---|
| SQLi | 500 | 9000001 | LAB SQLi denemesi (URI: 1=1) | 2 | local.rules |
| XSS | 200 | 9000002 | LAB XSS denemesi (URI: <script) | 2 | local.rules |
| XSS | 200 | 2009714 | ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt | 2 | ET Open |
| Path traversal | 200 | 9000003 | LAB Path traversal (URI: ../) | 1 | local.rules |
| Path traversal | 200 | 2049400 | ET WEB_SERVER /etc/passwd Detected in URI | 1 | ET Open |
| Scanner UA | 200 | 2008538 | ET SCAN Sqlmap SQL Injection Scan | 2 | ET Open |

Dört test türünün dördü de alarm üretti. Yerel kural 9000004 bu testte tetiklenmedi.

### Gürültü kaydı

| sid | İmza | Neden gürültü | Karar |
|---|---|---|---|
| 2002825 | ET INFO POSSIBLE Web Crawl using Curl | Saldırıya değil curl User-Agent'ına bakıyor; normal trafikte (40 istek) 2 alarm verdi. | Bırak (not edildi). Gerçek ortamda `threshold.config` ile suppress edilebilir. |
| 2210044 | SURICATA STREAM Packet with invalid timestamp | Docker sanal ağındaki TCP timestamp uyarısı; saldırıyla ilgisiz. | Bırak. Artarsa `threshold.config` ile suppress. |
| (grup) | dnp3-events / modbus-events (16 kural) | Endüstriyel protokoller, Juice Shop'la ilgisiz; `suricata.yaml`'da tespitleri kapalı olduğu için parse hatası veriyor. | `disable.conf` ile kapatıldı. |

### Gözlemler

- SQLi (`1=1`) yükünü yalnızca yerel kural 9000001 yakaladı; ET Open bu yük için alarm üretmedi. Yerel kurallar bu yüzden gerekli.
- Alarmların çoğu 2 kez görünüyor (istemci → nginx ve nginx → juice-shop).
- Path traversal alarmları 1 kez çıktı; nginx muhtemelen `../` ifadesini iletmeden önce normalleştiriyor.
- SQLi isteği HTTP 500 döndü: WAF `DetectionOnly` modunda olduğu için istek engellenmeden uygulamaya ulaştı.

## Karşılaşılan sorunlar ve çözümleri

| Belirti | Sebep | Çözüm |
|---|---|---|
| Logda tekrar eden `chown: ... Read-only file system`, konteyner sürekli yeniden başlıyor | İmajın başlangıç betiği `/etc/suricata` altındaki dosyaların sahibini değiştirmeye çalışıyor; dosyalar `:ro` bağlıydı | `docker-compose.yml` volume satırlarından `:ro` kaldırıldı |
| `protocol "dnp3"/"modbus" cannot be used in a signature` | Sadeleştirilmiş `suricata.yaml`'da bu protokollerin tespiti kapalı | `disable.conf`'a `group:dnp3-events.rules` ve `group:modbus-events.rules` eklendi, `suricata-update` tekrar çalıştırıldı |
| Eski servis sadece `local.rules` yüklüyordu | `command`'da `-S` bayrağı diğer tüm kuralları devre dışı bırakır | `command: ["-i", "eth0", "-k", "none"]` olarak değiştirildi |

## Doğrulama kontrol listesi

- [x] `suricata.rules` indirildi (ET Open)
- [x] Konteyner çalışıyor, logda "Engine started" var
- [x] Normal trafikte `eve.json`'a `http` olayları düştü
- [x] `test-waf.sh` sonrası `event_type: alert` kayıtları var
- [x] Gürültü tablosu dolduruldu

## Bilinen sınırlar

- Sadece düz HTTP görünür; nginx önünde TLS varsa içerik okunamaz (lab'da HTTP kullanılıyor).
- `EXTERNAL_NET: any` lab içindir; üretimde `!$HOME_NET` olmalıdır.
- ModSecurity engelleme moduna geçse bile istek nginx'e ulaştığı için Suricata yine alarm üretir. İki katmanın ayrı değerlendirilmesi için `eve.json` ile WAF audit logu karşılaştırılabilir.
