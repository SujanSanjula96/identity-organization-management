# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build entire project (skipping tests)
mvn clean install -DskipTests

# Build with tests
mvn clean install

# Build a single module
mvn clean install -DskipTests -pl components/org.wso2.carbon.identity.organization.management.application

# Run tests for a single module
mvn test -pl components/org.wso2.carbon.identity.organization.management.application

# Run a specific test class
mvn test -pl components/org.wso2.carbon.identity.organization.management.application -Dtest=OrgApplicationManagerImplTest

# Run checkstyle
mvn checkstyle:check

# Run spotbugs
mvn spotbugs:check

# Skip checkstyle and spotbugs during build
mvn clean install -DskipTests -Dcheckstyle.skip -Dspotbugs.skip
```

Java target version is 21. Test framework is TestNG with Mockito. H2 is used as the in-memory DB for tests.

## Architecture

This is a multi-module Maven project implementing **Organization Management** for WSO2 Identity Server (IS). Each component is packaged as an **OSGi bundle** deployed into the WSO2 Carbon runtime.

### OSGi / Carbon Conventions

Every component follows the same internal layout:
- `internal/` — contains a `ServiceComponent` (DS annotations to register/unregister OSGi services) and a `DataHolder` (singleton to hold injected service references)
- Service interfaces are in the component root package; implementations are `*Impl` classes
- DAO interfaces and `*DAOImpl` implementations handle DB access via `IdentityDatabaseUtil` (Carbon JDBC utilities)
- Event handlers extend Carbon's `AbstractEventHandler` or implement `ApplicationMgtListener`/`IdentityEventHandler` to hook into framework events

### Component Map

| Component | Purpose |
|---|---|
| `org.wso2.carbon.identity.organization.management.application` | Manages shared/fragment applications across the org hierarchy. Handles application sharing, fragmentation, and org-to-app mapping |
| `org.wso2.carbon.identity.organization.management.organization.user.sharing` | Manages sharing of users across orgs, including policy-based sharing (V2 API) |
| `org.wso2.carbon.identity.organization.resource.sharing.policy.management` | Stores and evaluates resource sharing policies (which resources are shared to which orgs under what policy) |
| `org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service` | Generic service for traversing an org hierarchy to resolve inherited resources. Uses a `Function<String, Optional<T>>` retriever + an `AggregationStrategy<T>` (first-found or merge-all) |
| `org.wso2.carbon.identity.organization.application.resource.hierarchy.traverse.service` | Application-specific variant of the hierarchy traversal service |
| `org.wso2.carbon.identity.organization.management.authz.service` | Authorization checks scoped to org management operations |
| `org.wso2.carbon.identity.organization.management.role.management.service` | Role management within an organization |
| `org.wso2.carbon.identity.organization.management.tenant.association` | Associates organizations with Carbon tenants |
| `org.wso2.carbon.identity.organization.management.tomcat.ext.tenant.resolver` | Resolves org/tenant context from HTTP requests in Tomcat |
| `org.wso2.carbon.identity.organization.management.governance.connector` | Governance connector (identity governance settings) for org management |
| `org.wso2.carbon.identity.organization.management.handler` | Event handlers triggered by org lifecycle events |
| `org.wso2.carbon.identity.organization.management.claim.provider` | Provides org-specific claims (e.g., org ID, org name) into tokens |
| `org.wso2.carbon.identity.organization.management.ext` | Extension points and listener interfaces for org management |
| `org.wso2.carbon.identity.organization.user.invitation.management` | Manages user invitations to join organizations |
| `org.wso2.carbon.identity.organization.config.service` | Per-org configuration storage |
| `org.wso2.carbon.identity.organization.discovery.service` | Org discovery (e.g., finding an org from a domain or email) |

**Core org management** (the org tree itself — CRUD for orgs, org hierarchy) lives in the external dependency `org.wso2.carbon.identity.organization.management.core` (artifact `identity-organization-management-core`), not in this repo.

### Key Patterns

**Hierarchy traversal** — `OrgResourceResolverService` walks from a given org up to the root, calling a caller-supplied `Function<String, Optional<T>>` at each level and aggregating results with an `AggregationStrategy`. Use `FirstFoundAggregationStrategy` to stop at the first hit or `MergeAllAggregationStrategy` to collect across all ancestors.

**Application sharing** — Applications created at a parent org can be "shared" to child orgs, which creates "fragment" applications in the child orgs. `OrgApplicationManager`/`OrgApplicationManagerImpl` and `OrgApplicationMgtDAO` manage this mapping. `FragmentApplicationMgtListener` intercepts application lifecycle events; `ApplicationSharingManagerListener` handles sharing-related events.

**User sharing** — `OrganizationUserSharingService` shares users from a parent org to child orgs. The V2 variant (`UserSharingPolicyHandlerServiceV2`) uses explicit policies stored in `resource-sharing-policy-management` for fine-grained control.

**Resource sharing policy** — `ResourceSharingPolicyHandlerService` stores and looks up policies that define how resources (apps, users, etc.) propagate across orgs. Policies are stored in DB via `ResourceSharingPolicyHandlerDAO`.

## Active Design Work (b2b-governance-planning/)

The `b2b-governance-planning/` directory contains design documents for the **Organization Capability Governance** feature — a mechanism for parent orgs to allow/deny specific capabilities for child orgs. See:
- `design/overview.md` — problem statement, goals, key concepts
- `design/data-model.md` — finalized DB schema and evaluation algorithm
- `context/org-management.md` — notes on the current IS org management implementation

This directory is design/documentation only and follows the conventions in `b2b-governance-planning/CLAUDE.md`.
