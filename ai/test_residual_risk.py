"""[S5][K4] Artık risk birim testleri (docs/olcum-metodolojisi.md Bölüm 4 örnekleri).

Çalıştırma:
    python -m unittest ai/test_residual_risk.py
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
        etkinlik, aktif, katildi = toplam_etkinlik_hesapla({"waf": "azaltir"}, "test")
        self.assertTrue(katildi)
        self.assertEqual(aktif, ["waf:azaltir"])
        self.assertAlmostEqual(etkinlik, 0.50, places=4)
        self.assertAlmostEqual(artik_risk_hesapla(9.8, etkinlik), 4.90, places=4)

    def test_ornek_2_v009_iam_engeller_test(self):
        """Metodoloji Örnek 2: V009 (7.5), IAM engeller/test -> etkinlik 0.90, risk_after 0.75."""
        etkinlik, aktif, katildi = toplam_etkinlik_hesapla({"iam": "engeller"}, "test")
        self.assertTrue(katildi)
        self.assertEqual(aktif, ["iam:engeller"])
        self.assertAlmostEqual(etkinlik, 0.90, places=4)
        self.assertAlmostEqual(artik_risk_hesapla(7.5, etkinlik), 0.75, places=4)

    def test_ornek_3_v022_waf_etkisiz(self):
        """Metodoloji Örnek 3: V022 (9.8), WAF etkisiz -> etkinlik 0.00, risk_after 9.80."""
        etkinlik, aktif, katildi = toplam_etkinlik_hesapla({"waf": "etkisiz"}, "test")
        self.assertTrue(katildi)
        self.assertEqual(aktif, [])
        self.assertAlmostEqual(etkinlik, 0.0, places=4)
        self.assertAlmostEqual(artik_risk_hesapla(9.8, etkinlik), 9.80, places=4)

    def test_coklu_kontrol_birlesimi_ve_bosluk_normalizasyonu(self):
        """Metodoloji Bölüm 3: WAF azaltir/test (0.50) + IDS tespit eder/gerekce (0.14) -> 0.57."""
        etkinlik_test, _, _ = toplam_etkinlik_hesapla(
            {"waf": "azaltir", "ids": "tespit eder"}, "test"
        )
        # 1 - (1 - 0.50) * (1 - 0.20) = 0.60
        self.assertAlmostEqual(etkinlik_test, 0.60, places=4)

        etkinlik_gerekce, _, _ = toplam_etkinlik_hesapla(
            {"waf": "azaltir", "ids": "tespit eder"}, "gerekce"
        )
        # 1 - (1 - 0.35) * (1 - 0.14) = 0.441
        self.assertAlmostEqual(etkinlik_gerekce, 0.441, places=4)

    def test_varsayim_dayanagi_hesaba_katilmaz_ve_isaretlenir(self):
        """dayanak = varsayim olan kayıtlar hesaba katılmamalı ve bayraklanmalıdır."""
        etkinlik, aktif, katildi = toplam_etkinlik_hesapla({"yama": "engeller"}, "varsayim")
        self.assertFalse(katildi)
        self.assertEqual(aktif, ["yama:engeller"])
        self.assertAlmostEqual(etkinlik, 0.0, places=4)
        self.assertAlmostEqual(artik_risk_hesapla(9.3, etkinlik), 9.3, places=4)

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