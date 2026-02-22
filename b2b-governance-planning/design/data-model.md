# B2B Governance — Data Model

## Schema

### UM_ORG_GOVERNANCE_POLICY

Governs a capability for an org-level scope (applies to all child orgs or selected child orgs under the governing org).

```sql
CREATE TABLE UM_ORG_GOVERNANCE_POLICY (
    UM_ID                VARCHAR(255) PRIMARY KEY,
    UM_RESOURCE_TYPE     VARCHAR(100) NOT NULL,
    UM_CAPABILITY        VARCHAR(100) NOT NULL,
    UM_GOVERNING_ORG_ID  VARCHAR(255) NOT NULL,
    UM_POLICY_TYPE       VARCHAR(100) NOT NULL,   -- ALL | IMMEDIATE | SELECTED | DENY
    UM_ALLOW_OVERRIDE    BOOLEAN      NOT NULL,
    UNIQUE (UM_GOVERNING_ORG_ID, UM_RESOURCE_TYPE, UM_CAPABILITY)
);
```

### UM_ORG_GOVERNANCE_ORG_SELECTED

Lists the specific orgs targeted when `UM_POLICY_TYPE = SELECTED` in `UM_ORG_GOVERNANCE_POLICY`.

```sql
CREATE TABLE UM_ORG_GOVERNANCE_ORG_SELECTED (
    UM_ID              VARCHAR(255) PRIMARY KEY,
    UM_POLICY_ID       VARCHAR(255) NOT NULL,
    UM_TARGET_ORG_ID   VARCHAR(255) NOT NULL,
    UM_ALLOW_OVERRIDE  BOOLEAN      NOT NULL,
    CONSTRAINT FK_ORG_GOV_POLICY
        FOREIGN KEY (UM_POLICY_ID)
        REFERENCES UM_ORG_GOVERNANCE_POLICY(UM_ID),
    UNIQUE (UM_POLICY_ID, UM_TARGET_ORG_ID)
);
```

### UM_RESOURCE_GOVERNANCE_POLICY

Governs a capability for a specific resource instance (e.g., one application) rather than all resources of a type.

```sql
CREATE TABLE UM_RESOURCE_GOVERNANCE_POLICY (
    UM_ID                    VARCHAR(255) PRIMARY KEY,
    UM_RESOURCE_TYPE         VARCHAR(100) NOT NULL,
    UM_RESOURCE_ID           VARCHAR(255) NOT NULL,
    UM_RESOURCE_OWNER_ORG_ID VARCHAR(255) NOT NULL,
    UM_GOVERNING_ORG_ID      VARCHAR(255) NOT NULL,
    UM_CAPABILITY            VARCHAR(100) NOT NULL,
    UM_POLICY_TYPE           VARCHAR(100) NOT NULL,   -- ALL | IMMEDIATE | SELECTED | DENY
    UM_ALLOW_OVERRIDE        BOOLEAN      NOT NULL,
    UNIQUE (UM_GOVERNING_ORG_ID, UM_RESOURCE_TYPE, UM_RESOURCE_ID, UM_CAPABILITY)
);
```

`UM_RESOURCE_OWNER_ORG_ID` and `UM_GOVERNING_ORG_ID` can be different orgs. The owner is the org that owns the resource; the governing org is the org setting the policy, which may differ when override rights have been delegated down the hierarchy.

### UM_RESOURCE_GOVERNANCE_ORG_SELECTED

Lists the specific orgs targeted when `UM_POLICY_TYPE = SELECTED` in `UM_RESOURCE_GOVERNANCE_POLICY`.

```sql
CREATE TABLE UM_RESOURCE_GOVERNANCE_ORG_SELECTED (
    UM_ID              VARCHAR(255) PRIMARY KEY,
    UM_POLICY_ID       VARCHAR(255) NOT NULL,
    UM_TARGET_ORG_ID   VARCHAR(255) NOT NULL,
    UM_ALLOW_OVERRIDE  BOOLEAN      NOT NULL,
    CONSTRAINT FK_RES_GOV_POLICY
        FOREIGN KEY (UM_POLICY_ID)
        REFERENCES UM_RESOURCE_GOVERNANCE_POLICY(UM_ID),
    UNIQUE (UM_POLICY_ID, UM_TARGET_ORG_ID)
);
```

---

## UM_POLICY_TYPE Values

| Value | Meaning |
|-------|---------|
| `ALL` | Applies to the entire subtree under the governing org |
| `IMMEDIATE` | Applies to direct children of the governing org only |
| `SELECTED` | Applies to the orgs explicitly listed in the corresponding `_ORG_SELECTED` table |
| `DENY` | Explicit deny for all children of the governing org |

---

## UM_ALLOW_OVERRIDE Semantics

**Policy-level** (on `UM_ORG_GOVERNANCE_POLICY` / `UM_RESOURCE_GOVERNANCE_POLICY`, used with `ALL` and `IMMEDIATE`):
Whether child orgs that receive the capability are permitted to create their own sub-governance policies for it.

**Selected-level** (on `_ORG_SELECTED` tables):
Per-org override right granted to that specific selected org only.

---

## Write-time Validation

An org may only create a governance policy for capability C if it was itself granted that capability with override rights. Specifically, one of the following must hold in the org's ancestry:

- An ancestor has `ALL` policy on C with `UM_ALLOW_OVERRIDE = true`, OR
- An ancestor has `IMMEDIATE` policy on C with `UM_ALLOW_OVERRIDE = true` and the org is that ancestor's direct child, OR
- The org appears in an ancestor's `SELECTED` list for C with `UM_ALLOW_OVERRIDE = true`

---

## Policy Evaluation Algorithm

**Goal:** determine whether org A has capability C on resource R.

Walk from org A's direct parent up to the root org. At each ancestor:

1. Is there a **resource-level** policy (in `UM_RESOURCE_GOVERNANCE_POLICY`) that covers org A for capability C on resource R?
   - If yes → return its result (ALLOW or DENY). **Stop.**
2. Is there an **org-level** policy (in `UM_ORG_GOVERNANCE_POLICY`) that covers org A for capability C?
   - If yes → return its result. **Stop.**
3. Neither applies → move to the next ancestor.

If the walk reaches the root org with no match → apply the external default for capability C (defaults are defined per capability outside this schema).

**Key properties:**
- Resource-level always takes priority over org-level at the same ancestor.
- The nearest ancestor that covers org A wins — a DENY closer in the hierarchy is a hard stop, even if a higher ancestor has an ALLOW.
- The walk does not continue past any matching policy.
