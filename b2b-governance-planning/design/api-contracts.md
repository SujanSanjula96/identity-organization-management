# B2B Governance — API Contracts

**Base path:** `/api/server/v1/governance-policies`

The governing org is derived from the auth token. `governingOrgId` is never in the request body — it is set server-side.

---

## Org-level Policies

### `POST /api/server/v1/governance-policies`
Create an org-level governance policy.

**Request**
```json
{
  "resourceType": "APPLICATION",
  "capability": "ADAPTIVE_SCRIPTS",
  "policyType": "SELECTED",
  "allowOverride": false,
  "selectedOrgs": [
    { "orgId": "org-123", "allowOverride": true }
  ]
}
```
`selectedOrgs` required only when `policyType = SELECTED`, ignored otherwise.

**Response `201`**
```json
{
  "resourceType": "APPLICATION",
  "capability": "ADAPTIVE_SCRIPTS",
  "governingOrgId": "governing-org-uuid",
  "policyType": "SELECTED",
  "allowOverride": false,
  "selectedOrgs": [
    { "orgId": "org-123", "allowOverride": true }
  ]
}
```

---

### `GET /api/server/v1/governance-policies`
List all org-level policies set by the governing org.

**Response `200`**
```json
[
  {
    "resourceType": "APPLICATION",
    "capability": "ADAPTIVE_SCRIPTS",
    "governingOrgId": "governing-org-uuid",
    "policyType": "ALL",
    "allowOverride": true,
    "selectedOrgs": []
  }
]
```

---

### `GET /api/server/v1/governance-policies/{resourceType}/{capability}`
Get a single org-level policy by its natural key.

**Response `200`** — same shape as above.
**Response `404`** — policy not found.

---

### `PUT /api/server/v1/governance-policies/{resourceType}/{capability}`
Update an org-level policy. `resourceType`, `capability`, and `governingOrgId` are immutable — only `policyType`, `allowOverride`, and `selectedOrgs` can change.

**Request**
```json
{
  "policyType": "ALL",
  "allowOverride": true,
  "selectedOrgs": []
}
```

**Response `200`** — updated policy, same shape as GET response.
**Response `404`** — policy not found.

---

### `DELETE /api/server/v1/governance-policies/{resourceType}/{capability}`
Delete an org-level policy.

**Response `204`**
**Response `404`** — policy not found.

---

## Resource-level Policies

### `POST /api/server/v1/resource-governance-policies`
Create a resource-level governance policy.

**Request**
```json
{
  "resourceType": "APPLICATION",
  "resourceId": "app-uuid",
  "resourceOwnerOrgId": "owner-org-uuid",
  "capability": "ADAPTIVE_SCRIPTS",
  "policyType": "SELECTED",
  "allowOverride": false,
  "selectedOrgs": [
    { "orgId": "org-123", "allowOverride": true }
  ]
}
```

**Response `201`**
```json
{
  "resourceType": "APPLICATION",
  "resourceId": "app-uuid",
  "resourceOwnerOrgId": "owner-org-uuid",
  "governingOrgId": "governing-org-uuid",
  "capability": "ADAPTIVE_SCRIPTS",
  "policyType": "SELECTED",
  "allowOverride": false,
  "selectedOrgs": [
    { "orgId": "org-123", "allowOverride": true }
  ]
}
```

---

### `GET /api/server/v1/resource-governance-policies`
List all resource-level policies set by the governing org.

**Response `200`** — array, same shape as above.

---

### `GET /api/server/v1/resource-governance-policies/{resourceType}/{resourceId}/{capability}`
Get a single resource-level policy by its natural key.

**Response `200`** — single policy.
**Response `404`** — not found.

---

### `PUT /api/server/v1/resource-governance-policies/{resourceType}/{resourceId}/{capability}`
`resourceType`, `resourceId`, `resourceOwnerOrgId`, `capability`, and `governingOrgId` are immutable.

**Request**
```json
{
  "policyType": "ALL",
  "allowOverride": true,
  "selectedOrgs": []
}
```

**Response `200`** — updated policy.
**Response `404`** — not found.

---

### `DELETE /api/server/v1/resource-governance-policies/{resourceType}/{resourceId}/{capability}`

**Response `204`**
**Response `404`** — not found.

---

## Error Responses

| Status | When |
|--------|------|
| `400` | Invalid request (e.g., `selectedOrgs` missing for SELECTED policy) |
| `403` | Governing org lacks override rights for the capability |
| `404` | Policy not found |
| `409` | Policy already exists for this (resource type, capability) combination |
