// Fonction pour initialiser les tooltips Bootstrap
function initTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Fonction pour initialiser les popovers Bootstrap
function initPopovers() {
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

// Fonction pour afficher/masquer les champs en fonction de la méthode de paiement
function handlePaymentMethodChange() {
    const paymentMethod = document.getElementById('payment_method');
    if (!paymentMethod) return;

    paymentMethod.addEventListener('change', function() {
        const method = this.value;
        document.getElementById('mobile_money_fields').style.display = 'none';
        document.getElementById('bank_transfer_fields').style.display = 'none';
        
        if (method === 'mobile_money') {
            document.getElementById('mobile_money_fields').style.display = 'block';
        } else if (method === 'bank_transfer') {
            document.getElementById('bank_transfer_fields').style.display = 'block';
        }
    });
}

// Initialisation lorsque le DOM est chargé
document.addEventListener('DOMContentLoaded', function() {
    initTooltips();
    initPopovers();
    handlePaymentMethodChange();
    
    // Initialiser les toasts s'ils existent
    const toastElList = [].slice.call(document.querySelectorAll('.toast'));
    const toastList = toastElList.map(function (toastEl) {
        return new bootstrap.Toast(toastEl, { autohide: true });
    });
    toastList.forEach(toast => toast.show());
    
    // Activer les onglets Bootstrap s'ils existent
    const tabEls = document.querySelectorAll('button[data-bs-toggle="tab"]');
    tabEls.forEach(tabEl => {
        tabEl.addEventListener('click', function (event) {
            event.preventDefault();
            const tab = new bootstrap.Tab(this);
            tab.show();
        });
    });
    
    // Gestion du téléchargement de fichiers
    const fileInputs = document.querySelectorAll('.form-control[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            const fileName = this.files[0]?.name || 'Aucun fichier sélectionné';
            const label = this.nextElementSibling;
            if (label && label.classList.contains('form-text')) {
                label.textContent = fileName;
            }
        });
    });
});
