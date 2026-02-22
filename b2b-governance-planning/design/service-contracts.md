# B2B Governance — Service Contracts

## DTOs

```java
public class OrgGovernancePolicy {
    String id;
    String resourceType;
    String capability;
    String governingOrgId;
    PolicyType policyType;
    boolean allowOverride;
    List<GovernanceOrgSelected> selectedOrgs;  // populated when policyType = SELECTED
}

public class ResourceGovernancePolicy {
    String id;
    String resourceType;
    String resourceId;
    String resourceOwnerOrgId;
    String governingOrgId;
    String capability;
    PolicyType policyType;
    boolean allowOverride;
    List<GovernanceOrgSelected> selectedOrgs;  // populated when policyType = SELECTED
}

public class GovernanceOrgSelected {
    String id;
    String policyId;
    String targetOrgId;
    boolean allowOverride;
}

public enum PolicyType {
    ALL, IMMEDIATE, SELECTED, DENY
}
```

## GovernancePolicyService

```java
public interface GovernancePolicyService {

    // Org-level policies
    OrgGovernancePolicy addOrgGovernancePolicy(OrgGovernancePolicy policy);
    OrgGovernancePolicy getOrgGovernancePolicy(String policyId);
    List<OrgGovernancePolicy> getOrgGovernancePolicies(String governingOrgId);
    OrgGovernancePolicy updateOrgGovernancePolicy(OrgGovernancePolicy policy);
    void deleteOrgGovernancePolicy(String policyId);

    // Resource-level policies
    ResourceGovernancePolicy addResourceGovernancePolicy(ResourceGovernancePolicy policy);
    ResourceGovernancePolicy getResourceGovernancePolicy(String policyId);
    List<ResourceGovernancePolicy> getResourceGovernancePolicies(String governingOrgId);
    ResourceGovernancePolicy updateResourceGovernancePolicy(ResourceGovernancePolicy policy);
    void deleteResourceGovernancePolicy(String policyId);
}
```

## GovernancePolicyEvaluator

```java
public interface GovernancePolicyEvaluator {

    // Evaluates both resource-level and org-level policies
    boolean evaluate(String orgId, String capability, String resourceType, String resourceId);

    // Evaluates org-level policies only (no specific resource in context)
    boolean evaluate(String orgId, String capability, String resourceType);
}
```
