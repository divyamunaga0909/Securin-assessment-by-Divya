# app.py
from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error
from datetime import datetime, timedelta
from flasgger import Swagger
from config import DATABASE_CONFIG

app = Flask(__name__)
swagger = Swagger(app)

def get_db_connection():
    try:
        conn = mysql.connector.connect(**DATABASE_CONFIG)
        return conn
    except Error as e:
        print(f"Error: {e}")
        return None

@app.route('/cve/<cve_id>', methods=['GET'])
def get_cve_by_id(cve_id):
    """
    Get CVE details by CVE ID
    ---
    parameters:
      - name: cve_id
        in: path
        type: string
        required: true
        description: The CVE ID
    responses:
      200:
        description: CVE details
        schema:
          id: CVE
          properties:
            cve_id:
              type: string
              description: The CVE ID
            description:
              type: string
              description: The description of the CVE
            base_score_v2:
              type: number
              description: CVSS v2 base score
            base_score_v3:
              type: number
              description: CVSS v3 base score
            last_modified:
              type: string
              description: The date the CVE was last modified
      404:
        description: CVE not found
    """
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE cve_id = %s", (cve_id,))
    cve = cursor.fetchone()
    cursor.close()
    conn.close()
    if cve:
        return jsonify(cve)
    return jsonify({'error': 'CVE not found'}), 404

@app.route('/cve/year/<int:year>', methods=['GET'])
def get_cve_by_year(year):
    """
    Get CVE details by year
    ---
    parameters:
      - name: year
        in: path
        type: integer
        required: true
        description: The year of the CVEs
    responses:
      200:
        description: List of CVEs for the specified year
        schema:
          type: array
          items:
            $ref: '#/definitions/CVE'
    """
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE YEAR(last_modified) = %s", (year,))
    cves = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(cves)

@app.route('/cve/score', methods=['GET'])
def get_cve_by_score():
    """
    Get CVE details by score range
    ---
    parameters:
      - name: min_score
        in: query
        type: number
        required: true
        description: The minimum CVSS score
      - name: max_score
        in: query
        type: number
        required: true
        description: The maximum CVSS score
    responses:
      200:
        description: List of CVEs within the specified score range
        schema:
          type: array
          items:
            $ref: '#/definitions/CVE'
    """
    min_score = request.args.get('min_score', type=float)
    max_score = request.args.get('max_score', type=float)
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM cve_details WHERE (base_score_v2 BETWEEN %s AND %s) OR (base_score_v3 BETWEEN %s AND %s)",
        (min_score, max_score, min_score, max_score)
    )
    cves = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(cves)

@app.route('/cve/modified/<int:days>', methods=['GET'])
def get_cve_modified_in_days(days):
    """
    Get CVE details modified in the last N days
    ---
    parameters:
      - name: days
        in: path
        type: integer
        required: true
        description: The number of days
    responses:
      200:
        description: List of CVEs modified in the last N days
        schema:
          type: array
          items:
            $ref: '#/definitions/CVE'
    """
    date_limit = datetime.now() - timedelta(days=days)
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM cve_details WHERE last_modified >= %s", (date_limit,))
    cves = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(cves)

if __name__ == '__main__':
    app.run(debug=True)
