
document.addEventListener('DOMContentLoaded', () => {
    const resultsPerPageSelect = document.getElementById('results-per-page');
    resultsPerPageSelect.addEventListener('change', loadCveData);
    loadCveData();
});

function loadCveData() {
    const resultsPerPage = document.getElementById('results-per-page').value;
    fetch(`/cve/list?resultsPerPage=${resultsPerPage}`)
        .then(response => response.json())
        .then(data => {
            const tableBody = document.querySelector('#cve-table tbody');
            tableBody.innerHTML = '';
            data.forEach(cve => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${cve.cve_id}</td>
                    <td>${cve.description}</td>
                    <td>${cve.base_score_v2}</td>
                    <td>${cve.base_score_v3}</td>
                    <td>${cve.last_modified}</td>
                `;
                tableBody.appendChild(row);
            });
        });
}
