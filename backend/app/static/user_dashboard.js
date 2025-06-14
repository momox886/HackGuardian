// dashboard.js

function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    const sections = document.querySelectorAll('.section');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => {
                t.classList.remove('active');
                t.setAttribute('aria-selected', 'false');
                t.setAttribute('tabindex', '-1');
            });
            sections.forEach(s => s.classList.remove('active'));

            tab.classList.add('active');
            tab.setAttribute('aria-selected', 'true');
            tab.setAttribute('tabindex', '0');

            const target = document.querySelector(tab.dataset.target);
            target.classList.add('active');
            target.focus();
        });
    });
}

function initDataTable() {
    $('#vuln-table').DataTable({
        responsive: true,
        pagingType: "simple",
        pageLength: 10,
        lengthChange: false,
        language: {
            url: "//cdn.datatables.net/plug-ins/1.13.4/i18n/fr-FR.json"
        },
        columnDefs: [
            { responsivePriority: 1, targets: 0 },
            { responsivePriority: 2, targets: 5 },
            { responsivePriority: 3, targets: 2 },
            { responsivePriority: 4, targets: 6 },
            { responsivePriority: 5, targets: 1 },
            { responsivePriority: 6, targets: 3 },
            { responsivePriority: 7, targets: 4 },
            { responsivePriority: 8, targets: 7 }
        ],
        order: [[2, 'desc']]
    });
}

function initCvssColors() {
    document.querySelectorAll('.cvss-badge[data-score]').forEach(badge => {
        const score = parseFloat(badge.getAttribute('data-score'));
        const hue = 120 - Math.max(0, Math.min(score / 10, 1)) * 120;
        const color = `hsl(${hue}, 85%, 55%)`;
        badge.style.backgroundColor = color;
        badge.style.boxShadow = `0 0 8px ${color}`;
    });
}

function initModal() {
    const table = document.getElementById('vuln-table');
    table.addEventListener('click', function (e) {
        const btn = e.target.closest('.btn-expand');
        if (!btn) return;
        const fullText = btn.getAttribute('data-fulltext');
        const container = document.createElement('div');
        container.className = 'slide-description';
        container.innerHTML = `
            <div class="slide-content">
                <button class="close-slide" aria-label="Fermer">&times;</button>
                <h4>Description complète</h4>
                <p>${fullText}</p>
            </div>
        `;

        document.body.appendChild(container);

        container.querySelector('.close-slide').addEventListener('click', () => {
            container.remove();
        });
    });
}

function showCriticalNotification(data) {
    const notifContainer = document.getElementById('critical-notification');
    const toast = document.createElement('div');
    toast.className = 'critical-toast';
    toast.innerHTML = `
        <div><strong>⚠ Nouvelle CVE critique !</strong></div>
        <div><strong>${data.cve_id}</strong></div>
        <div>Vendeur : ${data.vendor}</div>
        <div>Description : ${data.description}</div>
    `;
    notifContainer.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => toast.remove(), 400);
    }, 6000);
}

function initWebSocket() {
    const socket = io();
    const subscribedVendors = JSON.parse(document.getElementById("subscribed-vendors-json").textContent);

    subscribedVendors.forEach(v => socket.emit('join_vendor', v));
    socket.on('new_critical_cve', showCriticalNotification);
}

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initDataTable();
    initModal();
    initWebSocket();
    initCvssColors();
});
