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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.organization.management.capability.governance.dao.GovernancePolicyDAO;
import org.wso2.carbon.identity.organization.management.capability.governance.dao.GovernancePolicyDAOImpl;
import org.wso2.carbon.identity.organization.management.capability.governance.exception.GovernancePolicyMgtClientException;
import org.wso2.carbon.identity.organization.management.capability.governance.exception.GovernancePolicyMgtException;
import org.wso2.carbon.identity.organization.management.capability.governance.exception.GovernancePolicyMgtServerException;
import org.wso2.carbon.identity.organization.management.capability.governance.internal.GovernancePolicyDataHolder;
import org.wso2.carbon.identity.organization.management.capability.governance.model.GovernanceOrgSelected;
import org.wso2.carbon.identity.organization.management.capability.governance.model.OrgGovernancePolicy;
import org.wso2.carbon.identity.organization.management.capability.governance.model.PolicyType;
import org.wso2.carbon.identity.organization.management.capability.governance.model.ResourceGovernancePolicy;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.List;
import java.util.Optional;

import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_GET_ORG_POLICY_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_GET_RESOURCE_POLICY_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_HIERARCHY_TRAVERSAL_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_OVERRIDE_NOT_PERMITTED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_POLICY_NOT_FOUND;

/**
 * Implementation of {@link GovernancePolicyService}.
 */
public class GovernancePolicyServiceImpl implements GovernancePolicyService {

    private static final Log LOG = LogFactory.getLog(GovernancePolicyServiceImpl.class);
    private static final GovernancePolicyDAO GOVERNANCE_POLICY_DAO = new GovernancePolicyDAOImpl();

    @Override
    public OrgGovernancePolicy addOrgGovernancePolicy(OrgGovernancePolicy policy)
            throws GovernancePolicyMgtException {

        validateOrgGovernancePolicy(policy);
        String policyId = GOVERNANCE_POLICY_DAO.addOrgGovernancePolicy(policy);
        return GOVERNANCE_POLICY_DAO.getOrgGovernancePolicyById(policyId)
                .orElseThrow(() -> new GovernancePolicyMgtServerException(
                        ERROR_CODE_GET_ORG_POLICY_FAILED.getCode(),
                        ERROR_CODE_GET_ORG_POLICY_FAILED.getMessage(),
                        ERROR_CODE_GET_ORG_POLICY_FAILED.getDescription()));
    }

    @Override
    public OrgGovernancePolicy getOrgGovernancePolicy(String policyId) throws GovernancePolicyMgtException {

        return GOVERNANCE_POLICY_DAO.getOrgGovernancePolicyById(policyId)
                .orElseThrow(() -> new GovernancePolicyMgtClientException(
                        ERROR_CODE_POLICY_NOT_FOUND.getCode(),
                        ERROR_CODE_POLICY_NOT_FOUND.getMessage(),
                        ERROR_CODE_POLICY_NOT_FOUND.getDescription()));
    }

    @Override
    public List<OrgGovernancePolicy> getOrgGovernancePolicies(String governingOrgId)
            throws GovernancePolicyMgtException {

        return GOVERNANCE_POLICY_DAO.getOrgGovernancePoliciesByGoverningOrg(governingOrgId);
    }

    @Override
    public OrgGovernancePolicy updateOrgGovernancePolicy(OrgGovernancePolicy policy)
            throws GovernancePolicyMgtException {

        GOVERNANCE_POLICY_DAO.updateOrgGovernancePolicy(policy);
        return GOVERNANCE_POLICY_DAO.getOrgGovernancePolicyById(policy.getId())
                .orElseThrow(() -> new GovernancePolicyMgtClientException(
                        ERROR_CODE_POLICY_NOT_FOUND.getCode(),
                        ERROR_CODE_POLICY_NOT_FOUND.getMessage(),
                        ERROR_CODE_POLICY_NOT_FOUND.getDescription()));
    }

    @Override
    public void deleteOrgGovernancePolicy(String policyId) throws GovernancePolicyMgtException {

        GOVERNANCE_POLICY_DAO.deleteOrgGovernancePolicyById(policyId);
    }

    @Override
    public ResourceGovernancePolicy addResourceGovernancePolicy(ResourceGovernancePolicy policy)
            throws GovernancePolicyMgtException {

        String policyId = GOVERNANCE_POLICY_DAO.addResourceGovernancePolicy(policy);
        return GOVERNANCE_POLICY_DAO.getResourceGovernancePolicyById(policyId)
                .orElseThrow(() -> new GovernancePolicyMgtServerException(
                        ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getCode(),
                        ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getMessage(),
                        ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getDescription()));
    }

    @Override
    public ResourceGovernancePolicy getResourceGovernancePolicy(String policyId)
            throws GovernancePolicyMgtException {

        return GOVERNANCE_POLICY_DAO.getResourceGovernancePolicyById(policyId)
                .orElseThrow(() -> new GovernancePolicyMgtClientException(
                        ERROR_CODE_POLICY_NOT_FOUND.getCode(),
                        ERROR_CODE_POLICY_NOT_FOUND.getMessage(),
                        ERROR_CODE_POLICY_NOT_FOUND.getDescription()));
    }

    @Override
    public List<ResourceGovernancePolicy> getResourceGovernancePolicies(String governingOrgId)
            throws GovernancePolicyMgtException {

        return GOVERNANCE_POLICY_DAO.getResourceGovernancePoliciesByGoverningOrg(governingOrgId);
    }

    @Override
    public ResourceGovernancePolicy updateResourceGovernancePolicy(ResourceGovernancePolicy policy)
            throws GovernancePolicyMgtException {

        GOVERNANCE_POLICY_DAO.updateResourceGovernancePolicy(policy);
        return GOVERNANCE_POLICY_DAO.getResourceGovernancePolicyById(policy.getId())
                .orElseThrow(() -> new GovernancePolicyMgtClientException(
                        ERROR_CODE_POLICY_NOT_FOUND.getCode(),
                        ERROR_CODE_POLICY_NOT_FOUND.getMessage(),
                        ERROR_CODE_POLICY_NOT_FOUND.getDescription()));
    }

    @Override
    public void deleteResourceGovernancePolicy(String policyId) throws GovernancePolicyMgtException {

        GOVERNANCE_POLICY_DAO.deleteResourceGovernancePolicyById(policyId);
    }

    // -------------------------------------------------------------------------
    // Write-time validation
    // -------------------------------------------------------------------------

    private void validateOrgGovernancePolicy(OrgGovernancePolicy policy) throws GovernancePolicyMgtException {

        OrganizationManager organizationManager = GovernancePolicyDataHolder.getInstance().getOrganizationManager();
        try {
            if (organizationManager.isPrimaryOrganization(policy.getGoverningOrgId())) {
                // Root org is always allowed to create governance policies.
                return;
            }
            List<String> ancestors = organizationManager.getAncestorOrganizationIds(policy.getGoverningOrgId());
            // ancestors[0] = governingOrgId, ancestors[1] = direct parent, ...
            for (int i = 1; i < ancestors.size(); i++) {
                String ancestorId = ancestors.get(i);
                boolean isDirectParent = (i == 1);
                Optional<OrgGovernancePolicy> ancestorPolicy = GOVERNANCE_POLICY_DAO.findOrgGovernancePolicy(
                        ancestorId, policy.getCapability(), policy.getResourceType());
                if (ancestorPolicy.isPresent()) {
                    OrgGovernancePolicy ap = ancestorPolicy.get();
                    if (coversOrg(ap, policy.getGoverningOrgId(), isDirectParent) && ap.isAllowOverride()) {
                        return;
                    }
                }
            }
        } catch (OrganizationManagementException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_HIERARCHY_TRAVERSAL_FAILED.getCode(),
                    ERROR_CODE_HIERARCHY_TRAVERSAL_FAILED.getMessage(),
                    ERROR_CODE_HIERARCHY_TRAVERSAL_FAILED.getDescription(), e);
        }
        throw new GovernancePolicyMgtClientException(ERROR_CODE_OVERRIDE_NOT_PERMITTED.getCode(),
                ERROR_CODE_OVERRIDE_NOT_PERMITTED.getMessage(),
                ERROR_CODE_OVERRIDE_NOT_PERMITTED.getDescription());
    }

    /**
     * Returns true if the given policy at an ancestor covers the targetOrgId.
     */
    static boolean coversOrg(OrgGovernancePolicy policy, String targetOrgId, boolean isDirectChild) {

        switch (policy.getPolicyType()) {
            case ALL:
                return true;
            case DENY:
                return true;
            case IMMEDIATE:
                return isDirectChild;
            case SELECTED:
                return policy.getSelectedOrgs().stream()
                        .anyMatch(s -> targetOrgId.equals(s.getTargetOrgId()));
            default:
                return false;
        }
    }

    /**
     * Returns true if the given resource policy at an ancestor covers the targetOrgId.
     */
    static boolean coversOrg(ResourceGovernancePolicy policy, String targetOrgId, boolean isDirectChild) {

        switch (policy.getPolicyType()) {
            case ALL:
                return true;
            case DENY:
                return true;
            case IMMEDIATE:
                return isDirectChild;
            case SELECTED:
                return policy.getSelectedOrgs().stream()
                        .anyMatch(s -> targetOrgId.equals(s.getTargetOrgId()));
            default:
                return false;
        }
    }

    /**
     * Determines the effective allowOverride for a SELECTED-type policy for a specific org.
     */
    static boolean effectiveAllowOverride(OrgGovernancePolicy policy, String targetOrgId) {

        if (PolicyType.SELECTED.equals(policy.getPolicyType())) {
            return policy.getSelectedOrgs().stream()
                    .filter(s -> targetOrgId.equals(s.getTargetOrgId()))
                    .findFirst()
                    .map(GovernanceOrgSelected::isAllowOverride)
                    .orElse(false);
        }
        return policy.isAllowOverride();
    }
}
