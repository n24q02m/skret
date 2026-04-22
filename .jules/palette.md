## 2024-04-22 - Empty States for CLI Outputs
**Learning:** For empty collection states, returning actionable feedback (e.g., 'No secrets found. Use skret set...') significantly improves human readability and UX, but it's critical to return proper empty representations like `[]` for JSON to support programmatic parsing.
**Action:** Always provide actionable feedback for human-readable empty outputs (like tables) while retaining valid empty syntax (e.g. `[]`) for structured outputs (like JSON) to ensure both good UX and programmatic compatibility.
