document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-protocol-selector]').forEach((selector) => {
    const form = selector.closest('form');
    const smartFields = form?.querySelector('[data-smart-fields]');
    const smartRequiredInputs = form?.querySelectorAll('[data-smart-required]') || [];
    const checkboxes = selector.querySelectorAll('input[name="protocols[]"]');

    const syncSmartFields = () => {
      const smartSelected = Array.from(checkboxes).some((checkbox) => checkbox.value === 'smart' && checkbox.checked);

      if (smartFields) smartFields.hidden = !smartSelected;
      smartRequiredInputs.forEach((input) => {
        input.required = smartSelected;
      });
    };

    checkboxes.forEach((checkbox) => {
      checkbox.addEventListener('change', syncSmartFields);
    });
    syncSmartFields();
  });

  document.querySelectorAll('[data-protocol-workbench]').forEach((workbench) => {
    const tabs = workbench.querySelectorAll('[data-protocol-tab]');
    const panels = workbench.querySelectorAll('[data-protocol-panel]');

    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const selected = tab.dataset.protocolTab;

        tabs.forEach((candidate) => {
          candidate.classList.toggle('active', candidate === tab);
        });

        panels.forEach((panel) => {
          panel.hidden = selected !== 'all' && panel.dataset.protocolPanel !== selected;
        });
      });
    });
  });
});
