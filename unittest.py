import unittest
import json
from app import app

class CVEApiTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_get_cve_by_id(self):
        response = self.app.get('/cve/CVE-2021-34527')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.get_data(as_text=True))
        self.assertIn('cve_id', data)
        self.assertEqual(data['cve_id'], 'CVE-2021-34527')

    def test_get_cve_by_year(self):
        response = self.app.get('/cve/year/2021')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.get_data(as_text=True))
        self.assertIsInstance(data, list)

    def test_get_cve_by_score(self):
        response = self.app.get('/cve/score/9.0')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.get_data(as_text=True))
        self.assertIsInstance(data, list)

    def test_get_recent_cve(self):
        response = self.app.get('/cve/recent/30')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.get_data(as_text=True))
        self.assertIsInstance(data, list)

if __name__ == '__main__':
    unittest.main()
