// dashboard_admin.js

document.addEventListener("DOMContentLoaded", function () {
    // Bouton de chargement lors des soumissions
    const handleFormSubmit = (form) => {
        const button = form.querySelector('button[type="submit"]');
        if (button) {
            const originalText = button.innerHTML;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + button.textContent;
            button.disabled = true;

            setTimeout(() => {
                if (button.disabled) {
                    button.innerHTML = originalText;
                    button.disabled = false;
                }
            }, 5000);
        }
    };

    // Attacher aux formulaires
    document.querySelectorAll('.dashboard-form').forEach(form => {
        form.addEventListener('submit', function () {
            handleFormSubmit(this);
        });
    });

    // Auto-dismiss flash
    const flash = document.querySelector('.dashboard-flash');
    if (flash) {
        setTimeout(() => {
            flash.style.transition = 'opacity 0.5s ease';
            flash.style.opacity = '0';
            setTimeout(() => {
                flash.remove();
            }, 500);
        }, 5000);
    }

    // Focus style
    document.querySelectorAll('.dashboard-form input').forEach(input => {
        input.addEventListener('focus', function () {
            this.style.borderColor = 'var(--secondary)';
            this.style.boxShadow = '0 0 0 2px rgba(59, 130, 246, 0.2)';
        });

        input.addEventListener('blur', function () {
            this.style.borderColor = 'var(--border)';
            this.style.boxShadow = 'none';
        });
    });

    // Empêche le renvoi du formulaire au refresh
    if (window.history.replaceState) {
        window.history.replaceState(null, null, window.location.href);
    }
});
