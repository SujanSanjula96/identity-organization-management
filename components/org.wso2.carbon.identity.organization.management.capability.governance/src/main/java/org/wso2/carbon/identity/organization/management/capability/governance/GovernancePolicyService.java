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

    List<OrgGovernancePolicy> getOrgGovernancePolicies(String governingOrgId) throws GovernancePolicyMgtException;

    OrgGovernancePolicy updateOrgGovernancePolicy(OrgGovernancePolicy policy) throws GovernancePolicyMgtException;

    void deleteOrgGovernancePolicy(String policyId) throws GovernancePolicyMgtException;

    // -------------------------------------------------------------------------
    // Resource-level policies
    // -------------------------------------------------------------------------

    ResourceGovernancePolicy addResourceGovernancePolicy(ResourceGovernancePolicy policy)
            throws GovernancePolicyMgtException;

    ResourceGovernancePolicy getResourceGovernancePolicy(String policyId) throws GovernancePolicyMgtException;

    List<ResourceGovernancePolicy> getResourceGovernancePolicies(String governingOrgId)
            throws GovernancePolicyMgtException;

    ResourceGovernancePolicy updateResourceGovernancePolicy(ResourceGovernancePolicy policy)
            throws GovernancePolicyMgtException;

    void deleteResourceGovernancePolicy(String policyId) throws GovernancePolicyMgtException;
}
