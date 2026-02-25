(function(){
  'use strict';
  var modal, grid, searchInput, filterSelect, selectBtn;
  var targetInput = null;
  var selectedUrl = null;

  function init() {
    modal = document.getElementById('mediaPickerModal');
    grid = document.getElementById('mediaPickerGrid');
    searchInput = document.getElementById('mediaPickerSearch');
    filterSelect = document.getElementById('mediaPickerFilter');
    selectBtn = document.getElementById('mediaPickerSelect');
    if (!modal) return;

    document.querySelectorAll('[data-media-picker]').forEach(function(btn) {
      btn.addEventListener('click', function(e) {
        e.preventDefault();
        targetInput = document.getElementById(btn.getAttribute('data-media-picker'));
        openPicker();
      });
    });

    if (searchInput) searchInput.addEventListener('input', loadMedia);
    if (filterSelect) filterSelect.addEventListener('change', loadMedia);
    if (selectBtn) selectBtn.addEventListener('click', confirmSelection);
  }

  function openPicker() {
    selectedUrl = null;
    if (selectBtn) selectBtn.disabled = true;
    loadMedia();
    var bsModal = new bootstrap.Modal(modal);
    bsModal.show();
  }

  function loadMedia() {
    var q = searchInput ? searchInput.value : '';
    var mime = filterSelect ? filterSelect.value : '';
    var url = '/admin/media/api/picker?q=' + encodeURIComponent(q) + '&mime=' + encodeURIComponent(mime);
    fetch(url, { headers: { 'X-CSRF-Token': document.querySelector('[name=_csrf_token]')?.value || '' } })
      .then(function(r) { return r.json(); })
      .then(function(data) { renderGrid(data.items || []); })
      .catch(function() { grid.innerHTML = '<div class="text-center text-muted py-4">Failed to load media.</div>'; });
  }

  function renderGrid(items) {
    if (!items.length) {
      grid.innerHTML = '<div class="text-center text-muted py-4">No media found.</div>';
      return;
    }
    var html = '';
    items.forEach(function(item) {
      var isImage = (item.mime_type || '').startsWith('image/');
      var thumb = isImage ? '<img src="' + item.url + '" alt="' + (item.alt_text || '') + '" style="width:100%;height:120px;object-fit:cover;border-radius:6px;">' : '<div class="d-flex align-items-center justify-content-center" style="height:120px;background:rgba(255,255,255,.05);border-radius:6px;"><i class="fa-solid fa-file fa-2x"></i></div>';
      html += '<div class="col-6 col-md-3 col-lg-2">';
      html += '<div class="media-picker-item p-1 rounded" data-url="' + item.url + '" style="cursor:pointer;border:2px solid transparent;">';
      html += thumb;
      html += '<div class="text-truncate small mt-1">' + (item.filename || '') + '</div>';
      html += '</div></div>';
    });
    grid.innerHTML = html;

    grid.querySelectorAll('.media-picker-item').forEach(function(el) {
      el.addEventListener('click', function() {
        grid.querySelectorAll('.media-picker-item').forEach(function(x) { x.style.borderColor = 'transparent'; });
        el.style.borderColor = '#4f7bff';
        selectedUrl = el.getAttribute('data-url');
        if (selectBtn) selectBtn.disabled = false;
      });
    });
  }

  function confirmSelection() {
    if (selectedUrl && targetInput) {
      targetInput.value = selectedUrl;
      targetInput.dispatchEvent(new Event('change'));
    }
    bootstrap.Modal.getInstance(modal)?.hide();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
