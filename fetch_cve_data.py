import requests
import mysql.connector
from mysql.connector import Error

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATABASE_CONFIG = {
    'host': 'localhost',
    'database': 'cve_db',
    'user': 'root@localhost',
    'password': 'priyatham9'
}

def fetch_cve_data(start_index, results_per_page):
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page
    }
    response = requests.get(API_URL, params=params)
    return response.json()

def store_cve_data(cve_items):
    try:
        connection = mysql.connector.connect(**DATABASE_CONFIG)
        cursor = connection.cursor()
        insert_query = """
        INSERT INTO cve_details (cve_id, description, base_score_v2, base_score_v3, last_modified)
        VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            description = VALUES(description),
            base_score_v2 = VALUES(base_score_v2),
            base_score_v3 = VALUES(base_score_v3),
            last_modified = VALUES(last_modified);
        """
        data = [
            (
                cve['cve']['CVE_data_meta']['ID'],
                cve['cve']['description']['description_data'][0]['value'],
                cve.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore'),
                cve.get('impact', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore'),
                cve['lastModifiedDate']
            )
            for cve in cve_items
        ]
        cursor.executemany(insert_query, data)
        connection.commit()
    except Error as e:
        print(f"Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def main():
    start_index = 0
    results_per_page = 1000
    while True:
        cve_data = fetch_cve_data(start_index, results_per_page)
        if not cve_data.get('result', {}).get('CVE_Items'):
            break
        store_cve_data(cve_data['result']['CVE_Items'])
        start_index += results_per_page

if __name__ == "__main__":
    main()
