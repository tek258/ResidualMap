-# Günlük Git Akışı (PyCharm Terminali)

Bu akışı her görev için tekrarlayın. `main`'e doğrudan yazmıyoruz, her iş kendi branch'inde yapılıyor.

---

## 0. Bir kereye mahsus kurulum (her kişi kendi bilgisayarında)

```bash
git config --global user.name "kullanıcı adı"
git config --global user.email "github-hesabindaki-mail@ornek.com"
```

Repoyu klonlama (sadece ilk seferde):

```bash
git clone https://github.com/<kullanici-veya-org>/<repo-adi>.git
cd <repo-adi>
```

PyCharm'da: **File → Open** ile klonlanan klasörü açın. Alt taraftaki **Terminal** sekmesi zaten o klasörde açılır.

---

## 1. Her çalışmaya başlamadan önce

Önce `main`'i güncelleyin, yoksa eski kod üstüne çalışırsınız:

```bash
git checkout main
git pull origin main
```

Sonra **yeni bir branch** açın:

```bash
git checkout -b k2/hafta3-zap-tarama
```

Branch isim önerisi: `kisi/hafta-kisa-aciklama` (örn. `k4/hafta3-nvd-script`, `k5/hafta2-nginx-proxy`). Küçük harf, boşluk yerine tire.

Nerede olduğunuzu kontrol etmek için:

```bash
git branch
```

Yıldız (`*`) olan branch şu an içinde olduğunuz branch'tir. `main`'de yıldız varsa **kod yazmayın**, önce branch açın.

---

## 2. Çalışırken

Arada sırada durumu kontrol edin:

```bash
git status
```

Kırmızı = henüz eklenmemiş değişiklikler, yeşil = commit'e hazır olanlar.

---

## 3. Commit atma

```bash
git add .
git commit -m "ZAP baseline tarama çıktıları eklendi"
```

- `git add .` tüm değişiklikleri ekler. Sadece belirli dosya için: `git add dosya.py`
- Commit mesajı kısa ve ne yaptığınızı anlatan bir cümle olsun. "düzeltme", "deneme" gibi mesajlardan kaçının.
- Küçük ve sık commit atmak, tek büyük commit'ten iyidir.

---

## 4. GitHub'a gönderme (push)

İlk push'ta branch GitHub'da yoktur, şöyle gönderin:

```bash
git push -u origin k2/hafta3-zap-tarama
```

Aynı branch'e sonraki push'lar için sadece:

```bash
git push
```

---

## 5. Pull Request (PR) açma

1. GitHub'da repoya gidin, sarı şeritte **Compare & pull request** çıkar, tıklayın.
2. Başlık ve kısa açıklama yazın. Varsa issue numarasını ekleyin (`Closes #12`), böylece merge olunca kart kendiliğinden kapanır.
3. Sağdan **Reviewers** olarak K1'i (veya bir arkadaşınızı) seçin.
4. Onaylanınca **Merge pull request** ile `main`'e birleştirin.

PyCharm'da alternatif: sağ altta branch adına tıklayıp **New Branch**, commit için sol taraftaki **Commit** sekmesi. Ama terminal komutlarını öğrenmenizi öneririm, hata olunca çözmesi daha kolay.

---

## 6. PR birleştikten sonra

```bash
git checkout main
git pull origin main
git branch -d k2/hafta3-zap-tarama
```

Son komut eski branch'i yerelde siler. Sonra yeni görev için 1. adıma dönün.

---

## Özet: kısa kart

```bash
git checkout main
git pull origin main
git checkout -b kisi/hafta-konu
# ... çalış ...
git add .
git commit -m "ne yaptığını anlatan mesaj"
git push -u origin kisi/hafta-konu
# GitHub'da Pull Request aç
```

---

## Sık karşılaşılan sorunlar

**`git push` reddedildi / "rejected":** Uzaktaki branch'te sizde olmayan değişiklik var.

```bash
git pull origin <branch-adi>
git push
```

**Yanlışlıkla `main`'de değişiklik yaptım, henüz commit atmadım:**

```bash
git checkout -b yeni-branch-adi
```

Değişiklikler yeni branch'e taşınır, sonra normal commit atın.

**Yanlışlıkla `main`'e commit attım ama push etmedim:** Acele komut denemeyin. Önce ekipten birine veya bana danışın, güvenli şekilde geri alınabilir.

**Merge conflict (çakışma):** İki kişi aynı dosyanın aynı satırını değiştirmişse olur. PyCharm çakışmayı görsel olarak çözmeye yardım eder (dosyada **Resolve** butonu). Çözünce `git add .` ve `git commit` yapın. Bu yüzden herkesin farklı klasörde çalışması iyi: `inventory/`, `graph/`, `ai/`, `defense/`.

---

## Ekip kuralları

1. **Asla `main`'e doğrudan push yok.** GitHub'da zorlamak için: Settings → Branches → **Add branch protection rule** → `main` için "Require a pull request before merging" işaretleyin.
2. **Her PR en az bir kişi tarafından incelensin.** Yeni başlayanlar için hem öğrenme hem hata yakalama açısından çok faydalı.
3. **Büyük dosyaları (tarama çıktıları, modeller) ve şifreleri commit'lemeyin.** `.gitignore` ekleyin (PyCharm proje açarken Python şablonunu seçebilir). API anahtarlarını repoya koymayın, `.env` dosyasında tutup `.gitignore`'a ekleyin.
4. **Kanban ile bağlayın.** Branch ve PR açıklamasında issue numarasını yazmak kartların otomatik ilerlemesini sağlar.
