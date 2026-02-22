# Organization Capability Governance — Overview

## Problem Statement

WSO2 IS is expanding all root organization capabilities (application management, identity providers, API resources, users, groups, roles, actions, events, and more) to sub organizations at the product level. However, there is currently no mechanism for a root or parent organization to control which of these capabilities a child organization is allowed to use.

This means once a feature is enabled at the product level, all sub orgs under a root org gain access to it unconditionally — the parent org has no say in restricting or permitting individual capabilities for its children.

---

## Goals

- Allow a parent org to explicitly allow or deny specific capabilities for its child orgs, down to individual org or individual resource granularity.
- Support delegation: a parent can grant a child the right to further govern that capability within its own subtree.
- Support propagation: a policy can apply to the entire subtree (ALL), to direct children only (IMMEDIATE), or to a named subset (SELECTED).
- Keep evaluation deterministic: nearest ancestor wins; resource-level takes priority over org-level at the same ancestor.

## Non-Goals

- This is not about delegated action (a parent acting inside a child org on the child's behalf).
- This does not govern capabilities between sibling orgs or across root org boundaries.
- This does not replace product-level feature flags — governance operates within what is already enabled at the product level.

---

## Key Concepts

**Governing org** — the org that sets a governance policy. This is not necessarily the resource owner; it can be any org that has been granted override rights for that capability.

**Resource owner org** — the org that owns the resource being governed. Can differ from the governing org.

**Capability** — a discrete feature or permission being governed (e.g., adaptive scripts on applications).

**Policy type** — how broadly a policy applies: `ALL` (full subtree), `IMMEDIATE` (direct children only), `SELECTED` (named orgs only), or `DENY` (explicit deny for all children).

**Override rights** — whether orgs that receive a capability may in turn create governance policies for it within their own subtrees. Enforced at write time.

**External default** — the default allow/deny outcome for a capability when no governance policy covers an org. Defined per capability outside the governance schema; some capabilities default to allow, others to deny.
