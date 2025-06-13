// DOM Ready
document.addEventListener("DOMContentLoaded", function() {
    // Form Submission Handling
    const handleFormSubmit = (form) => {
        const button = form.querySelector('button[type="submit"]');
        if (button) {
            const originalText = button.innerHTML;
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> ' + button.textContent;
            button.disabled = true;
            
            // Reset button after 5 seconds if still disabled (fallback)
            setTimeout(() => {
                if (button.disabled) {
                    button.innerHTML = originalText;
                    button.disabled = false;
                }
            }, 5000);
        }
    };

    // Attach to all forms
    document.querySelectorAll('.index-form').forEach(form => {
        form.addEventListener('submit', function(e) {
            handleFormSubmit(this);
        });
    });

    // Flash Messages Auto-dismiss
    const flashMessages = document.querySelector('.index-flash');
    if (flashMessages) {
        setTimeout(() => {
            flashMessages.style.transition = 'opacity 0.5s ease';
            flashMessages.style.opacity = '0';
            setTimeout(() => {
                flashMessages.style.display = 'none';
            }, 500);
        }, 5000);
    }

    // Input Focus Effects
    document.querySelectorAll('.index-form input').forEach(input => {
        input.addEventListener('focus', function() {
            this.style.borderColor = 'var(--secondary)';
            this.style.boxShadow = '0 0 0 2px rgba(59, 130, 246, 0.2)';
        });
        
        input.addEventListener('blur', function() {
            this.style.borderColor = 'var(--border)';
            this.style.boxShadow = 'none';
        });
    });

    // Prevent form resubmission on page refresh
    if (window.history.replaceState) {
        window.history.replaceState(null, null, window.location.href);
    }
});