document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('[data-protocol-selector]').forEach((selector) => {
    const form = selector.closest('form');
    const smartFields = form?.querySelector('[data-smart-fields]');
    const udapFields = form?.querySelector('[data-udap-fields]');
    const smartRequiredInputs = form?.querySelectorAll('[data-smart-required]') || [];
    const checkboxes = selector.querySelectorAll('input[name="protocols[]"]');

    const syncProtocolFields = () => {
      const smartSelected = Array.from(checkboxes).some((checkbox) => checkbox.value === 'smart' && checkbox.checked);
      const udapSelected = Array.from(checkboxes).some((checkbox) => checkbox.value === 'udap' && checkbox.checked);

      if (smartFields) smartFields.hidden = !smartSelected;
      if (udapFields) udapFields.hidden = !udapSelected;
      smartRequiredInputs.forEach((input) => {
        input.required = smartSelected;
      });
    };

    checkboxes.forEach((checkbox) => {
      checkbox.addEventListener('change', syncProtocolFields);
    });
    syncProtocolFields();
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

  document.querySelectorAll('[data-udap-registration-form]').forEach((form) => {
    const grantInputs = form.querySelectorAll('input[name="grant_type"]');
    const authCodePanel = form.querySelector('[data-grant-panel="authorization_code"]');
    const authCodeInputs = authCodePanel?.querySelectorAll('input, textarea') || [];

    const syncGrantFields = () => {
      const selected = form.querySelector('input[name="grant_type"]:checked')?.value;
      const authCodeSelected = selected === 'authorization_code';

      if (authCodePanel) authCodePanel.hidden = !authCodeSelected;
      authCodeInputs.forEach((input) => {
        if (input.id === 'response_types') return;

        input.required = authCodeSelected;
      });
    };

    grantInputs.forEach((input) => {
      input.addEventListener('change', syncGrantFields);
    });
    syncGrantFields();
  });
});
