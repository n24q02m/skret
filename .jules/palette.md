## 2026-07-12 - Missing standard ARIA labels and column scopes in Skret Hub UI
**Learning:** The initial HTML generated for the dashboard and login forms in the `skret-hub` component lacked a visible label and column scope for basic accessibility. It's important to provide `aria-label`, `scope="col"`, and `role="alert"` attributes in manually authored strings or templates.
**Action:** Always include basic structural and contextual accessibility attributes when manually rendering HTML from string templates, even if it is a small or developer-focused tool.
