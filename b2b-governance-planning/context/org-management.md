# WSO2 IS — Organization Management: Current Implementation

## Root Organizations
- Root orgs are the top-level organizations in IS
- Each root org is a fully isolated tenant — no connection or awareness between root orgs
- The "super tenant" is simply the default root org created by the platform; it is not a special tier above others
- All root orgs are treated the same way

## Org Hierarchy
- Under each root org, organizations can be nested in a hierarchy of arbitrary depth
- Example: Root Org → Child Org → Grandchild Org → ...
- The root org itself acts as the parent org for its direct children

## Terminology
- **Root org**: the top-level org within an isolated tenant boundary
- **Parent org**: any org that has at least one child (includes the root org)
- **Child org**: any org that has a parent org above it in the hierarchy

## Feature Capabilities in Orgs
- Root orgs have a full feature set: application management, identity providers, API resources, users, groups, roles, actions, events, and more
- Child orgs share the same underlying tenant infrastructure but maintain separate org and hierarchy metadata
- Originally designed for B2B SaaS use cases (app sharing, enterprise IdP integration for sub orgs)
- Direction: all root org capabilities will eventually be available to sub orgs as well (feature gaps exist currently)

## Organization Capability Governance — Summary
- Feature name: **Organization Capability Governance**
- Governance applies downward only — parent restricts/allows capabilities for child orgs
- This is NOT delegated action (parent acting inside a child org)
- Full problem statement and key concepts: see `design/overview.md`
- Finalized schema and evaluation algorithm: see `design/data-model.md`

### Governance model at a glance
- A parent org sets a policy on a capability for a resource type (org-level) or a specific resource instance (resource-level)
- Policy types: `ALL` (full subtree), `IMMEDIATE` (direct children), `SELECTED` (named orgs), `DENY`
- `UM_ALLOW_OVERRIDE` controls whether receiving orgs can delegate further
- At write time, an org can only create a governance policy if its ancestor granted it override rights
- At eval time, walk from direct parent to root; nearest ancestor covering the org wins; resource-level beats org-level at the same ancestor; no match → external default applies
