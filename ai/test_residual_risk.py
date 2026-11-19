"""[S5][K4] Artık risk birim testleri (docs/olcum-metodolojisi.md Bölüm 4 örnekleri).

Çalıştırma:
    python -m unittest ai.test_residual_risk -v
"""

import unittest
from ai.residual_risk import (
    artik_risk_hesapla,
    toplam_etkinlik_hesapla,
    veri_yukle,
    tablo_uret,
)


class TestResidualRisk(unittest.TestCase):
    def test_ornek_1_v001_waf_azaltir_test(self):
        """Metodoloji Örnek 1: V001 (9.8), WAF azaltir/test -> etkinlik 0.50, risk_after 4.90."""
        etkinlik, aktif, katildi = toplam_etkinlik_hesapla({"waf": "azaltir"}, "test", vuln_id="V001")
        self.assertTrue(katildi)
        self.assertEqual(aktif, ["waf:azaltir"])
        self.assertAlmostEqual(etkinlik, 0.50, places=4)
        self.assertAlmostEqual(artik_risk_hesapla(9.8, etkinlik), 4.90, places=4)

    def test_ornek_2_v009_iam_engeller_test(self):
        """Metodoloji Örnek 2: V009 (7.5), IAM engeller/test -> etkinlik 0.90, risk_after 0.75."""
        etkinlik, aktif, katildi = toplam_etkinlik_hesapla({"iam": "engeller"}, "test", vuln_id="V009")
        self.assertTrue(katildi)
        self.assertEqual(aktif, ["iam:engeller"])
        self.assertAlmostEqual(etkinlik, 0.90, places=4)
        self.assertAlmostEqual(artik_risk_hesapla(7.5, etkinlik), 0.75, places=4)

    def test_ornek_3_v022_waf_etkisiz(self):
        """Metodoloji Örnek 3: V022 (9.8), WAF etkisiz -> etkinlik 0.00, risk_after 9.80."""
        etkinlik, aktif, katildi = toplam_etkinlik_hesapla({"waf": "etkisiz"}, "test", vuln_id="V022")
        self.assertTrue(katildi)
        self.assertEqual(aktif, [])
        self.assertAlmostEqual(etkinlik, 0.0, places=4)
        self.assertAlmostEqual(artik_risk_hesapla(9.8, etkinlik), 9.80, places=4)

    def test_coklu_kontrol_birlesimi_ve_bosluk_normalizasyonu(self):
        """Çoklu kontrol formülü 1 - Π(1 - e_i): test için 0.60 (0.50 & 0.20), gerekce için 0.441 (0.35 & 0.14)."""
        etkinlik_test, _, _ = toplam_etkinlik_hesapla(
            {"waf": "azaltir", "ids": "tespit eder"}, "test", vuln_id="V001"
        )
        # 1 - (1 - 0.50) * (1 - 0.20) = 0.60
        self.assertAlmostEqual(etkinlik_test, 0.60, places=4)

        etkinlik_gerekce, _, _ = toplam_etkinlik_hesapla(
            {"waf": "azaltir", "ids": "tespit eder"}, "gerekce", vuln_id="V004"
        )
        # 1 - (1 - 0.35) * (1 - 0.14) = 0.441
        self.assertAlmostEqual(etkinlik_gerekce, 0.441, places=4)

    def test_varsayim_dayanagi_hesaba_katilmaz_ve_isaretlenir(self):
        """dayanak = varsayim olan kayıtlar hesaba katılmamalı ve bayraklanmalıdır."""
        etkinlik, aktif, katildi = toplam_etkinlik_hesapla({"yama": "engeller"}, "varsayim", vuln_id="V022")
        self.assertFalse(katildi)
        self.assertEqual(aktif, ["yama:engeller"])
        self.assertAlmostEqual(etkinlik, 0.0, places=4)
        self.assertAlmostEqual(artik_risk_hesapla(9.3, etkinlik), 9.3, places=4)

    def test_bilinmeyen_etki_veya_dayanak_hata_verir(self):
        """Tanınmayan etki veya dayanak değeri sessizce 0 dönmemeli, kayıt+sütun+değer ile hata vermeli."""
        with self.assertRaises(ValueError) as ctx_dayanak:
            toplam_etkinlik_hesapla({"waf": "engeller"}, "gerekçe", vuln_id="V099")
        self.assertIn("V099", str(ctx_dayanak.exception))
        self.assertIn("dayanak", str(ctx_dayanak.exception))
        self.assertIn("gerekçe", str(ctx_dayanak.exception))

        with self.assertRaises(ValueError) as ctx_etki:
            toplam_etkinlik_hesapla({"waf": "engeler"}, "test", vuln_id="V098")
        self.assertIn("V098", str(ctx_etki.exception))
        self.assertIn("waf", str(ctx_etki.exception))
        self.assertIn("engeler", str(ctx_etki.exception))

    def test_eslemesi_olmayan_kayit_dusmez_isaretlenir(self):
        """control_mapping.csv içinde satırı olmayan zafiyet çıktıdan düşmemeli, 'eşleme yok' yazmalı."""
        sahte_kayit = [{
            "vuln_id": "V999",
            "risk_before": 8.2,
            "esleme_var": False,
            "kontroller_dict": {},
            "dayanak": "eşleme yok",
        }]
        sonuc = tablo_uret(sahte_kayit)
        self.assertEqual(len(sonuc), 1)
        self.assertEqual(sonuc[0]["dayanak"], "eşleme yok")
        self.assertEqual(sonuc[0]["hesaba_katildi"], "Hayır (eşleme yok)")
        self.assertEqual(sonuc[0]["risk_after"], 8.2)

    def test_tum_envanter_36_kayit_eksiksiz(self):
        """Kabul kriteri: 36 kaydın tamamı çıktıda olmalı ve varsayımlar işaretli olmalı."""
        kayitlar = veri_yukle()
        sonuclar = tablo_uret(kayitlar)
        self.assertEqual(len(sonuclar), 36)
        varsayimlar = [r for r in sonuclar if r["dayanak"] == "varsayim"]
        self.assertEqual(len(varsayimlar), 12)
        for v in varsayimlar:
            self.assertEqual(v["etkinlik"], 0.0)
            self.assertEqual(v["risk_after"], v["risk_before"])
            self.assertEqual(v["hesaba_katildi"], "Hayır (varsayim)")


if __name__ == "__main__":
    unittest.main()