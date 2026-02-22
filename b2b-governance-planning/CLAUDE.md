# Planning Workspace Instructions

## Context
- Product: WSO2 Identity Server
- Role: Associate Tech Lead (ATL) — design must be accurate and grounded, not speculative
- This workspace is design/documentation only — no implementation code

## How to Work

### Accuracy over completeness
- Do not pad design docs with boilerplate or filler sections
- Only write content that has been explicitly discussed and agreed upon
- If something is unclear, ask before writing it down

### File and folder discipline
- Do not create files or folders outside the current phase scope unless explicitly asked
- Do not write content into files unless asked to — confirm scope first

### IS implementation context
- The `context/` folder holds notes on current WSO2 IS implementations for reference in future design work
- Create separate `.md` files per topic on demand (e.g., `context/org-management.md`, `context/permission-model.md`)
- Do not create a context file until there is something concrete to capture
- Update existing context files when new related information is shared rather than creating duplicates

### Terminology
- If a term used seems ambiguous, WSO2-specific in a limiting way, or potentially better expressed differently, flag it and offer 2–3 neutral alternatives
- Do not silently rename or reframe concepts — always get confirmation before changing terminology in docs

### Proactive scenario thinking
- While discussing design, think about edge cases, alternative flows, and related scenarios that could affect the design
- Surface these as questions or observations — clearly marked as "something to consider"
- Never incorporate them into docs without explicit approval

### Communication style
- Keep responses concise and direct
- When proposing options, list them clearly with brief trade-offs
- Ask one focused question at a time when clarification is needed
