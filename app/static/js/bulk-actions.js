(function(){
  'use strict';
  var bar = document.getElementById('bulkActionsBar');
  var countEl = document.getElementById('bulkCount');
  var actionSelect = document.getElementById('bulkAction');
  var actionInput = document.getElementById('bulkActionInput');
  var idsInput = document.getElementById('bulkIdsInput');
  var applyBtn = document.getElementById('bulkApplyBtn');
  var cancelBtn = document.getElementById('bulkCancelBtn');
  var form = document.getElementById('bulkForm');
  var selectAllCheckbox = document.getElementById('bulkSelectAll');
  if (!bar || !selectAllCheckbox) return;

  var checkboxes = document.querySelectorAll('.bulk-checkbox');

  function updateBar() {
    var checked = document.querySelectorAll('.bulk-checkbox:checked');
    var count = checked.length;
    if (count > 0) {
      bar.classList.remove('d-none');
      bar.classList.add('d-flex');
    } else {
      bar.classList.add('d-none');
      bar.classList.remove('d-flex');
    }
    countEl.textContent = count;
    var ids = [];
    checked.forEach(function(cb) { ids.push(cb.value); });
    idsInput.value = ids.join(',');
  }

  selectAllCheckbox.addEventListener('change', function() {
    checkboxes.forEach(function(cb) { cb.checked = selectAllCheckbox.checked; });
    updateBar();
  });

  checkboxes.forEach(function(cb) {
    cb.addEventListener('change', updateBar);
  });

  if (actionSelect) {
    actionSelect.addEventListener('change', function() {
      actionInput.value = actionSelect.value;
      applyBtn.disabled = !actionSelect.value;
    });
  }

  if (cancelBtn) {
    cancelBtn.addEventListener('click', function() {
      selectAllCheckbox.checked = false;
      checkboxes.forEach(function(cb) { cb.checked = false; });
      updateBar();
    });
  }

  if (form) {
    form.addEventListener('submit', function(e) {
      var action = actionInput.value;
      if (!action) { e.preventDefault(); return; }
      if (action === 'delete' || action === 'trash') {
        if (!confirm('Are you sure you want to ' + action + ' the selected items?')) {
          e.preventDefault();
        }
      }
    });
  }
})();
