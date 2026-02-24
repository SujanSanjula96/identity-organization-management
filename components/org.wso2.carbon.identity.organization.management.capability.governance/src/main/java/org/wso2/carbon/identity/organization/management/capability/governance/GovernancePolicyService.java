/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.organization.management.capability.governance;

import org.wso2.carbon.identity.organization.management.capability.governance.exception.GovernancePolicyMgtException;
import org.wso2.carbon.identity.organization.management.capability.governance.model.OrgGovernancePolicy;
import org.wso2.carbon.identity.organization.management.capability.governance.model.ResourceGovernancePolicy;

import java.util.List;

/**
 * OSGi service interface for managing organization capability governance policies.
 */
public interface GovernancePolicyService {

    // -------------------------------------------------------------------------
    // Org-level policies
    // -------------------------------------------------------------------------

    OrgGovernancePolicy addOrgGovernancePolicy(OrgGovernancePolicy policy) throws GovernancePolicyMgtException;

    OrgGovernancePolicy getOrgGovernancePolicy(String policyId) throws GovernancePolicyMgtException;

    /**
     * Get an org-level policy by its natural key (governingOrgId + resourceType + capability).
     * Maps to GET /governance-policies/{resourceType}/{capability}.
     */
    OrgGovernancePolicy getOrgGovernancePolicyByKey(String governingOrgId, String resourceType, String capability)
            throws GovernancePolicyMgtException;

    List<OrgGovernancePolicy> getOrgGovernancePolicies(String governingOrgId) throws GovernancePolicyMgtException;

    OrgGovernancePolicy updateOrgGovernancePolicy(OrgGovernancePolicy policy) throws GovernancePolicyMgtException;

    /**
     * Update an org-level policy identified by its natural key.
     * Only policyType, allowOverride, and selectedOrgs in {@code updates} are applied.
     * Maps to PUT /governance-policies/{resourceType}/{capability}.
     */
    OrgGovernancePolicy updateOrgGovernancePolicyByKey(String governingOrgId, String resourceType, String capability,
            OrgGovernancePolicy updates) throws GovernancePolicyMgtException;

    void deleteOrgGovernancePolicy(String policyId) throws GovernancePolicyMgtException;

    /**
     * Delete an org-level policy by its natural key.
     * Maps to DELETE /governance-policies/{resourceType}/{capability}.
     */
    void deleteOrgGovernancePolicyByKey(String governingOrgId, String resourceType, String capability)
            throws GovernancePolicyMgtException;

    // -------------------------------------------------------------------------
    // Resource-level policies
    // -------------------------------------------------------------------------

    ResourceGovernancePolicy addResourceGovernancePolicy(ResourceGovernancePolicy policy)
            throws GovernancePolicyMgtException;

    ResourceGovernancePolicy getResourceGovernancePolicy(String policyId) throws GovernancePolicyMgtException;

    /**
     * Get a resource-level policy by its natural key.
     * Maps to GET /resource-governance-policies/{resourceType}/{resourceId}/{capability}.
     */
    ResourceGovernancePolicy getResourceGovernancePolicyByKey(String governingOrgId, String resourceType,
            String resourceId, String capability) throws GovernancePolicyMgtException;

    List<ResourceGovernancePolicy> getResourceGovernancePolicies(String governingOrgId)
            throws GovernancePolicyMgtException;

    ResourceGovernancePolicy updateResourceGovernancePolicy(ResourceGovernancePolicy policy)
            throws GovernancePolicyMgtException;

    /**
     * Update a resource-level policy identified by its natural key.
     * Only policyType, allowOverride, and selectedOrgs in {@code updates} are applied.
     * Maps to PUT /resource-governance-policies/{resourceType}/{resourceId}/{capability}.
     */
    ResourceGovernancePolicy updateResourceGovernancePolicyByKey(String governingOrgId, String resourceType,
            String resourceId, String capability, ResourceGovernancePolicy updates)
            throws GovernancePolicyMgtException;

    void deleteResourceGovernancePolicy(String policyId) throws GovernancePolicyMgtException;

    /**
     * Delete a resource-level policy by its natural key.
     * Maps to DELETE /resource-governance-policies/{resourceType}/{resourceId}/{capability}.
     */
    void deleteResourceGovernancePolicyByKey(String governingOrgId, String resourceType, String resourceId,
            String capability) throws GovernancePolicyMgtException;
}
