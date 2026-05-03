## 2026-05-03 - Semantic PR Title Requirement
**Learning:** The CI pipeline enforces semantic pull request titles using `amannn/action-semantic-pull-request`. My previous PR title "⚡ Bolt: Add fast path..." failed this check because it lacked a valid prefix (like `feat:` or `fix:`). The correct format required by the AGENTS.md constraints for the Bolt persona is `feat: ⚡ bolt: [performance improvement]`.
**Action:** Always format PR titles with the `feat: ` or `fix: ` prefix before the persona emoji and name to pass CI semantic release checks.
