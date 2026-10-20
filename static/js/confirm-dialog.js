// Styled replacement for window.confirm(), built on a Bootstrap modal.
// Usage: if (!(await confirmDialog({ title, message, confirmText }))) return;
(function () {
    let modalEl = null;
    let modal = null;

    function build() {
        modalEl = document.createElement('div');
        modalEl.className = 'modal fade confirm-dialog';
        modalEl.tabIndex = -1;
        modalEl.setAttribute('aria-hidden', 'true');
        modalEl.setAttribute('aria-labelledby', 'confirmDialogTitle');
        modalEl.innerHTML =
            '<div class="modal-dialog modal-dialog-centered modal-sm-plus">' +
            '  <div class="modal-content">' +
            '    <div class="modal-body text-center">' +
            '      <div class="confirm-icon"><i class="fa-solid fa-trash-can"></i></div>' +
            '      <h5 class="confirm-title" id="confirmDialogTitle"></h5>' +
            '      <p class="confirm-message"></p>' +
            '      <div class="confirm-actions">' +
            '        <button type="button" class="btn btn-light confirm-cancel" data-bs-dismiss="modal">Cancel</button>' +
            '        <button type="button" class="btn btn-danger confirm-ok"></button>' +
            '      </div>' +
            '    </div>' +
            '  </div>' +
            '</div>';
        document.body.appendChild(modalEl);
        modal = new bootstrap.Modal(modalEl);
    }

    window.confirmDialog = function (options) {
        const opts = Object.assign({
            title: 'Are you sure?',
            message: 'This action cannot be undone.',
            confirmText: 'Delete',
            cancelText: 'Cancel',
        }, options || {});

        if (!modalEl) build();

        modalEl.querySelector('.confirm-title').textContent = opts.title;
        modalEl.querySelector('.confirm-message').textContent = opts.message;
        modalEl.querySelector('.confirm-cancel').textContent = opts.cancelText;
        const okButton = modalEl.querySelector('.confirm-ok');
        okButton.textContent = opts.confirmText;

        return new Promise(function (resolve) {
            let confirmed = false;

            function onOk() {
                confirmed = true;
                modal.hide();
            }

            function onShown() {
                // Focus Cancel so pressing Enter by accident does not delete
                modalEl.querySelector('.confirm-cancel').focus();
            }

            function onHidden() {
                okButton.removeEventListener('click', onOk);
                modalEl.removeEventListener('shown.bs.modal', onShown);
                modalEl.removeEventListener('hidden.bs.modal', onHidden);
                resolve(confirmed);
            }

            okButton.addEventListener('click', onOk);
            modalEl.addEventListener('shown.bs.modal', onShown);
            modalEl.addEventListener('hidden.bs.modal', onHidden);
            modal.show();
        });
    };
})();
