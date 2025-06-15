document.addEventListener("DOMContentLoaded", function () {
    // Initialisation unique de DataTable
    $('#vuln-table').DataTable({
        responsive: true,
        pagingType: "simple", // Seulement Précédent / Suivant
        pageLength: 10,
        lengthChange: false,  // Cache le menu déroulant de nombre d'éléments par page
        language: {
            url: "//cdn.datatables.net/plug-ins/1.13.4/i18n/fr-FR.json"
        },
        columnDefs: [
            { responsivePriority: 1, targets: 0 }, // CVE ID
            { responsivePriority: 2, targets: 5 }, // Description
            { responsivePriority: 3, targets: 2 }, // Score CVSS
            { responsivePriority: 4, targets: 6 }, // Exploitation
            { responsivePriority: 5, targets: 1 }, // Fournisseur
            { responsivePriority: 6, targets: 3 }, // Vecteur
            { responsivePriority: 7, targets: 4 }, // CWE
            { responsivePriority: 8, targets: 7 }  // Date
        ],
        order: [[2, 'desc']] // Tri par score CVSS décroissant par défaut
    });

    // Gestion des boutons d'expansion de description
    document.querySelectorAll('.btn-expand').forEach(btn => {
        btn.addEventListener('click', function () {
            const modal = document.getElementById('descriptionModal');
            const modalBody = modal.querySelector('.modal-body');
            modalBody.textContent = this.dataset.fulltext;
            modal.style.display = 'block';
        });
    });

    // Fermeture du modal
    document.querySelector('.close-modal').addEventListener('click', function () {
        document.getElementById('descriptionModal').style.display = 'none';
    });

    // Fermer le modal en cliquant à l'extérieur
    window.addEventListener('click', function (event) {
        const modal = document.getElementById('descriptionModal');
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
});
