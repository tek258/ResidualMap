# ResidualMap - Saldırı Yolu Risk Değerlendirme Metodolojisi

Bu doküman, `ResidualMap` projesinde tespit edilen saldırı yollarının (attack paths) kantitatif (sayısal) olarak risk puanlanmasının yapılabilmesi için seçilen metodolojiyi, alternatiflerin karşılaştırmasını ve örnek hesaplamaları içermektedir.

---

## 1. Yöntem Alternatiflerinin Karşılaştırılması

Saldırı grafiğindeki her bir yolun tek bir risk skoruyla ifade edilebilmesi için iki farklı yaklaşım incelenmiştir:

### a) Yoldaki En Yüksek CVSS Skoru (Maximum CVSS Approach)
* **Tanım:** Yol üzerinde bulunan zafiyetlerin en yüksek CVSS taban puanını doğrudan yolun risk skoru olarak kabul eder.
* **Avantajları:** Hesaplaması basittir ve bilinen standart metriklere (CVSS) dayanır.
* **Dezavantajları:** Saldırı yolunun uzunluğunu (adım sayısını) dikkate almaz. Çok uzun ve başarılı olma ihtimali düşük bir zincir ile tek adımlık kritik bir zafiyete aynı puanı verebilir. Ayrıca hedefin iş açısından kritiklik değerini (business impact) hesaba katmaz.

### b) Sömürülme Olasılıklarının Çarpımı × Hedef Kritikliği (Multiplicative Probability-Criticality Model) - *SEÇİLEN*
* **Tanım:** Zincir üzerindeki her bir zafiyetin sömürülme olasılığı ($P_i$) birbiriyle çarpılır (zincirleme başarı olasılığı) ve varış noktasındaki hedefin kritiklik katsayısı ($C_{\text{target}}$) ile ölçeklenir.
* **Formül:** 
  $$\text{Risk} = \left(\prod_{i=1}^{n} P_i\right) \times C_{\text{target}}$$
* **Avantajları:** 
  * Çok adımlı saldırıların doğasındaki kümülatif başarı zorluğunu (adım sayısı arttıkça toplam olasılığın düşmesini) doğru şekilde yansıtır.
  * Kurumsal etkiyi göz önüne alarak admin paneli veya RCE gibi kritik hedeflere öncelik verir.

---

## 2. Yöntem Seçimi ve Gerekçesi

Karşılaştırma sonucunda **(b) Sömürülme Olasılıklarının Çarpımı × Hedef Kritikliği** modeli seçilmiştir. 

**Gerekçe:** Siber güvenlikte çok adımlı saldırı yolları (path exploitation), zincirdeki zayıf halkalar nedeniyle adım sayısı arttıkça zorlaşır. Olasılıkların çarpımı modeli bu gerçekçi siber risk matematiğini (`AND` bağıntısı mantığını) simüle eder. Ayrıca hedef varlığın iş süreçlerindeki önem derecesinin ($C_{\text{target}}$) hesaba katılması, güvenlik ekiplerinin gerçek iş etkisine (business impact) göre aksiyon almasını sağlar.

---

## 3. Parametre Tanımları

* **Zafiyet Olasılıkları ($P_i$):** 0.0 ile 1.0 arasında değişen sömürü edilebilirlik katsayıları (Örn: `V031` = 0.80, `V014` = 0.75, `V001` = 0.70).
* **Hedef Kritiklik Skorları ($C_{\text{target}}$):**
  * `node_target_admin`: 10.0
  * `node_target_rce`: 10.0
  * `node_target_account_takeover`: 9.0
  * `node_target_leak`: 8.0
  * `node_target_dos`: 6.0

---

## 4. `paths.json` Üzerinden 3 Örnek Yol ile Manuel Hesaplama

### Örnek Yol 1: Doğrudan Admin Erişimi (Kısa Zincir)
* **Yol Düğümleri:** `node_entry_login` $\rightarrow$ `V014` $\rightarrow$ `node_target_admin`
* **Hesaplama:**
  * $P(\text{V014}) = 0.75$
  * $C_{\text{target}}(\text{node\_target\_admin}) = 10.0$
  * $\text{Risk} = 0.75 \times 10.0 = \mathbf{7.50}$

### Örnek Yol 2: RCE Hedefli Kritik Zafiyet
* **Yol Düğümleri:** `node_entry_login` $\rightarrow$ `V031` $\rightarrow$ `node_target_rce`
* **Hesaplama:**
  * $P(\text{V031}) = 0.80$
  * $C_{\text{target}}(\text{node\_target\_rce}) = 10.0$
  * $\text{Risk} = 0.80 \times 10.0 = \mathbf{8.00}$

### Örnek Yol 3: Çok Adımlı Admin Erişim Zinciri
* **Yol Düğümleri:** `node_entry_api` $\rightarrow$ `V002` $\rightarrow$ `V025` $\rightarrow$ `node_target_admin`
* **Hesaplama:**
  * $P(\text{V002}) = 0.40$, $P(\text{V025}) = 0.50$
  * $C_{\text{target}}(\text{node\_target\_admin}) = 10.0$
  * Olasılıklar Çarpımı: $0.40 \times 0.50 = 0.20$
  * $\text{Risk} = 0.20 \times 10.0 = \mathbf{2.00}$