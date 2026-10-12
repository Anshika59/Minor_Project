document.addEventListener('DOMContentLoaded', () => {
  // 1. Primary Form Tab Switching (Paste vs Upload)
  const tabBtns = document.querySelectorAll('.tabs-nav .tab-btn');
  const tabPanes = document.querySelectorAll('.tab-content');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');

      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(targetId);
      if (targetPane) {
        targetPane.classList.add('active');
      }
    });
  });

  // 2. Quick Sample Chips Loader
  const sampleChips = document.querySelectorAll('.sample-chip');
  const textarea = document.getElementById('email_text');

  sampleChips.forEach(chip => {
    chip.addEventListener('click', async () => {
      const sampleId = chip.getAttribute('data-sample');
      try {
        const resp = await fetch(`/api/samples/${sampleId}`);
        const data = await resp.json();
        if (data.status === 'success' && data.content) {
          // Switch to paste tab
          const pasteTabBtn = document.querySelector('[data-tab="tab-paste"]');
          if (pasteTabBtn) pasteTabBtn.click();

          if (textarea) {
            textarea.value = data.content;
            textarea.focus();
            // Highlight chip briefly
            chip.style.borderColor = '#3b82f6';
            setTimeout(() => { chip.style.borderColor = ''; }, 1000);
          }
        }
      } catch (err) {
        console.error('Failed to load sample:', err);
      }
    });
  });

  // 3. Drag and Drop File Upload
  const dropArea = document.getElementById('drop-area');
  const fileInput = document.getElementById('email_file');
  const filenameDisplay = document.getElementById('selected-filename');

  if (dropArea && fileInput) {
    ['dragenter', 'dragover'].forEach(eventName => {
      dropArea.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropArea.classList.add('dragover');
      }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropArea.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropArea.classList.remove('dragover');
      }, false);
    });

    dropArea.addEventListener('drop', (e) => {
      const dt = e.dataTransfer;
      const files = dt.files;
      if (files.length > 0) {
        fileInput.files = files;
        updateFilename(files[0].name);
      }
    });

    fileInput.addEventListener('change', () => {
      if (fileInput.files.length > 0) {
        updateFilename(fileInput.files[0].name);
      }
    });
  }

  function updateFilename(name) {
    if (filenameDisplay) {
      filenameDisplay.textContent = `Selected: ${name}`;
    }
  }

  // 4. Clear Form Button
  const btnClear = document.getElementById('btn-clear');
  if (btnClear) {
    btnClear.addEventListener('click', () => {
      if (textarea) textarea.value = '';
      if (fileInput) fileInput.value = '';
      if (filenameDisplay) filenameDisplay.textContent = '';
    });
  }

  // 5. Inspection Drawer Tabs Switching
  const inspectTabBtns = document.querySelectorAll('.inspection-tabs .inspect-tab-btn');
  const inspectPanes = document.querySelectorAll('.inspect-tab-pane');

  inspectTabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');

      inspectTabBtns.forEach(b => b.classList.remove('active'));
      inspectPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetPane = document.getElementById(targetId);
      if (targetPane) {
        targetPane.classList.add('active');
      }
    });
  });
});
