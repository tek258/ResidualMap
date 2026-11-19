# ResidualMap

AI destekli, saldırı grafiği tabanlı bir güvenlik mimarisi prototipi.
Bilinen zafiyetleri saldırı yollarına dönüştürür, yapay zeka ile önceliklendirir,
katmanlı bir savunma tasarlar ve savunma öncesi/sonrası artık riski ölçer.

## Proje Özeti

- **Hedef uygulama:** [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
- **Ders:** Engineering Design II
- **Süre:** 10 hafta

## Ekip

| Kişi | Rol | GitHub |
|---|---|---|
| [Ekrem Arda Kınık] | Proje Yöneticisi / Entegrasyon | [@Tek258](https://github.com/Tek258) |
| [Arda Şahindokucuyu] | Zafiyet Envanteri | [@Leroy0734](https://github.com/Leroy0734) |
| [Göktürk Ulutaş] | Saldırı Grafiği | [@GokturkUlutas](https://github.com/GokturkUlutas) |
| [Fatih Yılmaz] | AI ile Önceliklendirme | [@FatihYilmaz449](https://github.com/FatihYilmaz449) |
| [Engin Armağan] | Savunma Mimarisi | [@EnginArmagan](https://github.com/EnginArmagan) |

## Yöntem

1. **Envanter** — Hedef uygulamadaki bilinen zafiyetleri tara, CVSS ile puanla
2. **Saldırı Grafiği** — Zafiyetleri MITRE ATT&CK / CAPEC ile ilişkilendirip saldırı yolları çıkar
3. **AI ile Önceliklendirme** — Saldırı yollarını ML/LLM tabanlı bir modelle risk sırasına koy
4. **Savunma Mimarisi** — WAF, IDS/IPS, SIEM, IAM ve ağ segmentasyonu ile katmanlı savunma kur
5. **Artık Risk Ölçümü** — Savunma öncesi ve sonrası riski karşılaştır

## Klasör Yapısı
    residualmap/
    ├── docs/ → notlar, özetler, mimari diyagramlar, toplantı notları
    ├── inventory/ → zafiyet envanteri ve ham tarama çıktıları
    ├── graph/ → saldırı grafiği kodu ve görselleştirmeleri
    ├── ai/ → risk skorlama modeli, veri ve sonuçlar
    ├── defense/ → WAF, IDS, SIEM, ağ segmentasyonu yapılandırmaları
    └── report/ → teknik rapor ve görseller

## Veri Akış Şekli
![Veri akışı](docs/veri-akisi.png)
Düz oklar scriptlerle otomatik, kesikli oklar elle yapılan adımları gösterir. Tüm tablolar vuln_id ile birleşir.

## Lisans

Bu proje eğitim amaçlıdır. Hedef uygulama olan OWASP Juice Shop MIT lisansı ile dağıtılmaktadır.

