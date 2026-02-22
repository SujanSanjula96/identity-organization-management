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

package org.wso2.carbon.identity.organization.management.capability.governance.dao;

import org.wso2.carbon.database.utils.jdbc.NamedJdbcTemplate;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.database.utils.jdbc.exceptions.TransactionException;
import org.wso2.carbon.identity.organization.management.capability.governance.exception.GovernancePolicyMgtServerException;
import org.wso2.carbon.identity.organization.management.capability.governance.model.GovernanceOrgSelected;
import org.wso2.carbon.identity.organization.management.capability.governance.model.OrgGovernancePolicy;
import org.wso2.carbon.identity.organization.management.capability.governance.model.PolicyType;
import org.wso2.carbon.identity.organization.management.capability.governance.model.ResourceGovernancePolicy;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.COL_UM_ALLOW_OVERRIDE;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.COL_UM_CAPABILITY;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.COL_UM_GOVERNING_ORG_ID;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.COL_UM_ID;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.COL_UM_POLICY_ID;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.COL_UM_POLICY_TYPE;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.COL_UM_RESOURCE_ID;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.COL_UM_RESOURCE_OWNER_ORG_ID;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.COL_UM_RESOURCE_TYPE;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.COL_UM_TARGET_ORG_ID;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_ADD_ORG_POLICY_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_ADD_RESOURCE_POLICY_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_DELETE_ORG_POLICY_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_DELETE_RESOURCE_POLICY_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_GET_ORG_POLICY_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_GET_RESOURCE_POLICY_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_UPDATE_ORG_POLICY_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicyConstants.ErrorMessage.ERROR_CODE_UPDATE_RESOURCE_POLICY_FAILED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.DELETE_ORG_GOVERNANCE_ORG_SELECTED_BY_POLICY;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.DELETE_ORG_GOVERNANCE_POLICY_BY_ID;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.DELETE_RESOURCE_GOVERNANCE_ORG_SELECTED_BY_POLICY;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.DELETE_RESOURCE_GOVERNANCE_POLICY_BY_ID;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.INSERT_ORG_GOVERNANCE_ORG_SELECTED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.INSERT_ORG_GOVERNANCE_POLICY;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.INSERT_RESOURCE_GOVERNANCE_ORG_SELECTED;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.INSERT_RESOURCE_GOVERNANCE_POLICY;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.SELECT_ORG_GOVERNANCE_ORG_SELECTED_BY_POLICY;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.SELECT_ORG_GOVERNANCE_POLICIES_BY_GOVERNING_ORG;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.SELECT_ORG_GOVERNANCE_POLICY_BY_GOVERNING_ORG_AND_CAPABILITY;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.SELECT_ORG_GOVERNANCE_POLICY_BY_ID;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.SELECT_RESOURCE_GOVERNANCE_ORG_SELECTED_BY_POLICY;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.SELECT_RESOURCE_GOVERNANCE_POLICIES_BY_GOVERNING_ORG;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.SELECT_RESOURCE_GOVERNANCE_POLICY_BY_GOVERNING_ORG_AND_CAPABILITY;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.SELECT_RESOURCE_GOVERNANCE_POLICY_BY_ID;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.UPDATE_ORG_GOVERNANCE_POLICY;
import static org.wso2.carbon.identity.organization.management.capability.governance.constant.GovernancePolicySQLConstants.UPDATE_RESOURCE_GOVERNANCE_POLICY;
import static org.wso2.carbon.identity.organization.management.service.util.Utils.getNewTemplate;

/**
 * DAO implementation for managing organization capability governance policies.
 */
public class GovernancePolicyDAOImpl implements GovernancePolicyDAO {

    @Override
    public String addOrgGovernancePolicy(OrgGovernancePolicy policy) throws GovernancePolicyMgtServerException {

        String policyId = UUID.randomUUID().toString();
        policy.setId(policyId);

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.withTransaction(template -> {
                template.executeUpdate(INSERT_ORG_GOVERNANCE_POLICY, namedPreparedStatement -> {
                    namedPreparedStatement.setString(COL_UM_ID, policyId);
                    namedPreparedStatement.setString(COL_UM_RESOURCE_TYPE, policy.getResourceType());
                    namedPreparedStatement.setString(COL_UM_CAPABILITY, policy.getCapability());
                    namedPreparedStatement.setString(COL_UM_GOVERNING_ORG_ID, policy.getGoverningOrgId());
                    namedPreparedStatement.setString(COL_UM_POLICY_TYPE, policy.getPolicyType().name());
                    namedPreparedStatement.setBoolean(COL_UM_ALLOW_OVERRIDE, policy.isAllowOverride());
                });
                if (PolicyType.SELECTED.equals(policy.getPolicyType()) && policy.getSelectedOrgs() != null) {
                    for (GovernanceOrgSelected selected : policy.getSelectedOrgs()) {
                        String selectedId = UUID.randomUUID().toString();
                        selected.setId(selectedId);
                        selected.setPolicyId(policyId);
                        template.executeUpdate(INSERT_ORG_GOVERNANCE_ORG_SELECTED, namedPreparedStatement -> {
                            namedPreparedStatement.setString(COL_UM_ID, selectedId);
                            namedPreparedStatement.setString(COL_UM_POLICY_ID, policyId);
                            namedPreparedStatement.setString(COL_UM_TARGET_ORG_ID, selected.getTargetOrgId());
                            namedPreparedStatement.setBoolean(COL_UM_ALLOW_OVERRIDE, selected.isAllowOverride());
                        });
                    }
                }
                return null;
            });
        } catch (TransactionException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_ADD_ORG_POLICY_FAILED.getCode(),
                    ERROR_CODE_ADD_ORG_POLICY_FAILED.getMessage(),
                    ERROR_CODE_ADD_ORG_POLICY_FAILED.getDescription(), e);
        }
        return policyId;
    }

    @Override
    public Optional<OrgGovernancePolicy> getOrgGovernancePolicyById(String policyId)
            throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            OrgGovernancePolicy policy = namedJdbcTemplate.fetchSingleRecord(
                    SELECT_ORG_GOVERNANCE_POLICY_BY_ID,
                    (resultSet, rowNum) -> mapOrgGovernancePolicy(resultSet),
                    namedPreparedStatement -> namedPreparedStatement.setString(COL_UM_ID, policyId));
            if (policy != null) {
                populateOrgSelectedOrgs(policy);
            }
            return Optional.ofNullable(policy);
        } catch (DataAccessException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_GET_ORG_POLICY_FAILED.getCode(),
                    ERROR_CODE_GET_ORG_POLICY_FAILED.getMessage(),
                    ERROR_CODE_GET_ORG_POLICY_FAILED.getDescription(), e);
        }
    }

    @Override
    public List<OrgGovernancePolicy> getOrgGovernancePoliciesByGoverningOrg(String governingOrgId)
            throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            List<OrgGovernancePolicy> policies = namedJdbcTemplate.executeQuery(
                    SELECT_ORG_GOVERNANCE_POLICIES_BY_GOVERNING_ORG,
                    (resultSet, rowNum) -> mapOrgGovernancePolicy(resultSet),
                    namedPreparedStatement ->
                            namedPreparedStatement.setString(COL_UM_GOVERNING_ORG_ID, governingOrgId));
            for (OrgGovernancePolicy policy : policies) {
                populateOrgSelectedOrgs(policy);
            }
            return policies;
        } catch (DataAccessException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_GET_ORG_POLICY_FAILED.getCode(),
                    ERROR_CODE_GET_ORG_POLICY_FAILED.getMessage(),
                    ERROR_CODE_GET_ORG_POLICY_FAILED.getDescription(), e);
        }
    }

    @Override
    public void updateOrgGovernancePolicy(OrgGovernancePolicy policy) throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.withTransaction(template -> {
                template.executeUpdate(UPDATE_ORG_GOVERNANCE_POLICY, namedPreparedStatement -> {
                    namedPreparedStatement.setString(COL_UM_POLICY_TYPE, policy.getPolicyType().name());
                    namedPreparedStatement.setBoolean(COL_UM_ALLOW_OVERRIDE, policy.isAllowOverride());
                    namedPreparedStatement.setString(COL_UM_ID, policy.getId());
                });
                // Replace selected orgs.
                template.executeUpdate(DELETE_ORG_GOVERNANCE_ORG_SELECTED_BY_POLICY,
                        namedPreparedStatement ->
                                namedPreparedStatement.setString(COL_UM_POLICY_ID, policy.getId()));
                if (PolicyType.SELECTED.equals(policy.getPolicyType()) && policy.getSelectedOrgs() != null) {
                    for (GovernanceOrgSelected selected : policy.getSelectedOrgs()) {
                        String selectedId = UUID.randomUUID().toString();
                        selected.setId(selectedId);
                        selected.setPolicyId(policy.getId());
                        template.executeUpdate(INSERT_ORG_GOVERNANCE_ORG_SELECTED, namedPreparedStatement -> {
                            namedPreparedStatement.setString(COL_UM_ID, selectedId);
                            namedPreparedStatement.setString(COL_UM_POLICY_ID, policy.getId());
                            namedPreparedStatement.setString(COL_UM_TARGET_ORG_ID, selected.getTargetOrgId());
                            namedPreparedStatement.setBoolean(COL_UM_ALLOW_OVERRIDE, selected.isAllowOverride());
                        });
                    }
                }
                return null;
            });
        } catch (TransactionException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_UPDATE_ORG_POLICY_FAILED.getCode(),
                    ERROR_CODE_UPDATE_ORG_POLICY_FAILED.getMessage(),
                    ERROR_CODE_UPDATE_ORG_POLICY_FAILED.getDescription(), e);
        }
    }

    @Override
    public void deleteOrgGovernancePolicyById(String policyId) throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.executeUpdate(DELETE_ORG_GOVERNANCE_POLICY_BY_ID,
                    namedPreparedStatement -> namedPreparedStatement.setString(COL_UM_ID, policyId));
        } catch (DataAccessException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_DELETE_ORG_POLICY_FAILED.getCode(),
                    ERROR_CODE_DELETE_ORG_POLICY_FAILED.getMessage(),
                    ERROR_CODE_DELETE_ORG_POLICY_FAILED.getDescription(), e);
        }
    }

    @Override
    public String addResourceGovernancePolicy(ResourceGovernancePolicy policy)
            throws GovernancePolicyMgtServerException {

        String policyId = UUID.randomUUID().toString();
        policy.setId(policyId);

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.withTransaction(template -> {
                template.executeUpdate(INSERT_RESOURCE_GOVERNANCE_POLICY, namedPreparedStatement -> {
                    namedPreparedStatement.setString(COL_UM_ID, policyId);
                    namedPreparedStatement.setString(COL_UM_RESOURCE_TYPE, policy.getResourceType());
                    namedPreparedStatement.setString(COL_UM_RESOURCE_ID, policy.getResourceId());
                    namedPreparedStatement.setString(COL_UM_RESOURCE_OWNER_ORG_ID, policy.getResourceOwnerOrgId());
                    namedPreparedStatement.setString(COL_UM_GOVERNING_ORG_ID, policy.getGoverningOrgId());
                    namedPreparedStatement.setString(COL_UM_CAPABILITY, policy.getCapability());
                    namedPreparedStatement.setString(COL_UM_POLICY_TYPE, policy.getPolicyType().name());
                    namedPreparedStatement.setBoolean(COL_UM_ALLOW_OVERRIDE, policy.isAllowOverride());
                });
                if (PolicyType.SELECTED.equals(policy.getPolicyType()) && policy.getSelectedOrgs() != null) {
                    for (GovernanceOrgSelected selected : policy.getSelectedOrgs()) {
                        String selectedId = UUID.randomUUID().toString();
                        selected.setId(selectedId);
                        selected.setPolicyId(policyId);
                        template.executeUpdate(INSERT_RESOURCE_GOVERNANCE_ORG_SELECTED, namedPreparedStatement -> {
                            namedPreparedStatement.setString(COL_UM_ID, selectedId);
                            namedPreparedStatement.setString(COL_UM_POLICY_ID, policyId);
                            namedPreparedStatement.setString(COL_UM_TARGET_ORG_ID, selected.getTargetOrgId());
                            namedPreparedStatement.setBoolean(COL_UM_ALLOW_OVERRIDE, selected.isAllowOverride());
                        });
                    }
                }
                return null;
            });
        } catch (TransactionException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_ADD_RESOURCE_POLICY_FAILED.getCode(),
                    ERROR_CODE_ADD_RESOURCE_POLICY_FAILED.getMessage(),
                    ERROR_CODE_ADD_RESOURCE_POLICY_FAILED.getDescription(), e);
        }
        return policyId;
    }

    @Override
    public Optional<ResourceGovernancePolicy> getResourceGovernancePolicyById(String policyId)
            throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            ResourceGovernancePolicy policy = namedJdbcTemplate.fetchSingleRecord(
                    SELECT_RESOURCE_GOVERNANCE_POLICY_BY_ID,
                    (resultSet, rowNum) -> mapResourceGovernancePolicy(resultSet),
                    namedPreparedStatement -> namedPreparedStatement.setString(COL_UM_ID, policyId));
            if (policy != null) {
                populateResourceSelectedOrgs(policy);
            }
            return Optional.ofNullable(policy);
        } catch (DataAccessException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getCode(),
                    ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getMessage(),
                    ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getDescription(), e);
        }
    }

    @Override
    public List<ResourceGovernancePolicy> getResourceGovernancePoliciesByGoverningOrg(String governingOrgId)
            throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            List<ResourceGovernancePolicy> policies = namedJdbcTemplate.executeQuery(
                    SELECT_RESOURCE_GOVERNANCE_POLICIES_BY_GOVERNING_ORG,
                    (resultSet, rowNum) -> mapResourceGovernancePolicy(resultSet),
                    namedPreparedStatement ->
                            namedPreparedStatement.setString(COL_UM_GOVERNING_ORG_ID, governingOrgId));
            for (ResourceGovernancePolicy policy : policies) {
                populateResourceSelectedOrgs(policy);
            }
            return policies;
        } catch (DataAccessException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getCode(),
                    ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getMessage(),
                    ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getDescription(), e);
        }
    }

    @Override
    public void updateResourceGovernancePolicy(ResourceGovernancePolicy policy)
            throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.withTransaction(template -> {
                template.executeUpdate(UPDATE_RESOURCE_GOVERNANCE_POLICY, namedPreparedStatement -> {
                    namedPreparedStatement.setString(COL_UM_POLICY_TYPE, policy.getPolicyType().name());
                    namedPreparedStatement.setBoolean(COL_UM_ALLOW_OVERRIDE, policy.isAllowOverride());
                    namedPreparedStatement.setString(COL_UM_ID, policy.getId());
                });
                // Replace selected orgs.
                template.executeUpdate(DELETE_RESOURCE_GOVERNANCE_ORG_SELECTED_BY_POLICY,
                        namedPreparedStatement ->
                                namedPreparedStatement.setString(COL_UM_POLICY_ID, policy.getId()));
                if (PolicyType.SELECTED.equals(policy.getPolicyType()) && policy.getSelectedOrgs() != null) {
                    for (GovernanceOrgSelected selected : policy.getSelectedOrgs()) {
                        String selectedId = UUID.randomUUID().toString();
                        selected.setId(selectedId);
                        selected.setPolicyId(policy.getId());
                        template.executeUpdate(INSERT_RESOURCE_GOVERNANCE_ORG_SELECTED, namedPreparedStatement -> {
                            namedPreparedStatement.setString(COL_UM_ID, selectedId);
                            namedPreparedStatement.setString(COL_UM_POLICY_ID, policy.getId());
                            namedPreparedStatement.setString(COL_UM_TARGET_ORG_ID, selected.getTargetOrgId());
                            namedPreparedStatement.setBoolean(COL_UM_ALLOW_OVERRIDE, selected.isAllowOverride());
                        });
                    }
                }
                return null;
            });
        } catch (TransactionException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_UPDATE_RESOURCE_POLICY_FAILED.getCode(),
                    ERROR_CODE_UPDATE_RESOURCE_POLICY_FAILED.getMessage(),
                    ERROR_CODE_UPDATE_RESOURCE_POLICY_FAILED.getDescription(), e);
        }
    }

    @Override
    public void deleteResourceGovernancePolicyById(String policyId) throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            namedJdbcTemplate.executeUpdate(DELETE_RESOURCE_GOVERNANCE_POLICY_BY_ID,
                    namedPreparedStatement -> namedPreparedStatement.setString(COL_UM_ID, policyId));
        } catch (DataAccessException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_DELETE_RESOURCE_POLICY_FAILED.getCode(),
                    ERROR_CODE_DELETE_RESOURCE_POLICY_FAILED.getMessage(),
                    ERROR_CODE_DELETE_RESOURCE_POLICY_FAILED.getDescription(), e);
        }
    }

    @Override
    public Optional<OrgGovernancePolicy> findOrgGovernancePolicy(String governingOrgId, String capability,
            String resourceType) throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            OrgGovernancePolicy policy = namedJdbcTemplate.fetchSingleRecord(
                    SELECT_ORG_GOVERNANCE_POLICY_BY_GOVERNING_ORG_AND_CAPABILITY,
                    (resultSet, rowNum) -> mapOrgGovernancePolicy(resultSet),
                    namedPreparedStatement -> {
                        namedPreparedStatement.setString(COL_UM_GOVERNING_ORG_ID, governingOrgId);
                        namedPreparedStatement.setString(COL_UM_CAPABILITY, capability);
                        namedPreparedStatement.setString(COL_UM_RESOURCE_TYPE, resourceType);
                    });
            if (policy != null && PolicyType.SELECTED.equals(policy.getPolicyType())) {
                populateOrgSelectedOrgs(policy);
            }
            return Optional.ofNullable(policy);
        } catch (DataAccessException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_GET_ORG_POLICY_FAILED.getCode(),
                    ERROR_CODE_GET_ORG_POLICY_FAILED.getMessage(),
                    ERROR_CODE_GET_ORG_POLICY_FAILED.getDescription(), e);
        }
    }

    @Override
    public Optional<ResourceGovernancePolicy> findResourceGovernancePolicy(String governingOrgId, String capability,
            String resourceType, String resourceId) throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            ResourceGovernancePolicy policy = namedJdbcTemplate.fetchSingleRecord(
                    SELECT_RESOURCE_GOVERNANCE_POLICY_BY_GOVERNING_ORG_AND_CAPABILITY,
                    (resultSet, rowNum) -> mapResourceGovernancePolicy(resultSet),
                    namedPreparedStatement -> {
                        namedPreparedStatement.setString(COL_UM_GOVERNING_ORG_ID, governingOrgId);
                        namedPreparedStatement.setString(COL_UM_CAPABILITY, capability);
                        namedPreparedStatement.setString(COL_UM_RESOURCE_TYPE, resourceType);
                        namedPreparedStatement.setString(COL_UM_RESOURCE_ID, resourceId);
                    });
            if (policy != null && PolicyType.SELECTED.equals(policy.getPolicyType())) {
                populateResourceSelectedOrgs(policy);
            }
            return Optional.ofNullable(policy);
        } catch (DataAccessException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getCode(),
                    ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getMessage(),
                    ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getDescription(), e);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private OrgGovernancePolicy mapOrgGovernancePolicy(ResultSet rs) throws SQLException {

        OrgGovernancePolicy policy = new OrgGovernancePolicy();
        policy.setId(rs.getString(COL_UM_ID));
        policy.setResourceType(rs.getString(COL_UM_RESOURCE_TYPE));
        policy.setCapability(rs.getString(COL_UM_CAPABILITY));
        policy.setGoverningOrgId(rs.getString(COL_UM_GOVERNING_ORG_ID));
        policy.setPolicyType(PolicyType.valueOf(rs.getString(COL_UM_POLICY_TYPE)));
        policy.setAllowOverride(rs.getBoolean(COL_UM_ALLOW_OVERRIDE));
        return policy;
    }

    private ResourceGovernancePolicy mapResourceGovernancePolicy(ResultSet rs) throws SQLException {

        ResourceGovernancePolicy policy = new ResourceGovernancePolicy();
        policy.setId(rs.getString(COL_UM_ID));
        policy.setResourceType(rs.getString(COL_UM_RESOURCE_TYPE));
        policy.setResourceId(rs.getString(COL_UM_RESOURCE_ID));
        policy.setResourceOwnerOrgId(rs.getString(COL_UM_RESOURCE_OWNER_ORG_ID));
        policy.setGoverningOrgId(rs.getString(COL_UM_GOVERNING_ORG_ID));
        policy.setCapability(rs.getString(COL_UM_CAPABILITY));
        policy.setPolicyType(PolicyType.valueOf(rs.getString(COL_UM_POLICY_TYPE)));
        policy.setAllowOverride(rs.getBoolean(COL_UM_ALLOW_OVERRIDE));
        return policy;
    }

    private void populateOrgSelectedOrgs(OrgGovernancePolicy policy) throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            List<GovernanceOrgSelected> selectedOrgs = namedJdbcTemplate.executeQuery(
                    SELECT_ORG_GOVERNANCE_ORG_SELECTED_BY_POLICY,
                    (resultSet, rowNum) -> mapGovernanceOrgSelected(resultSet),
                    namedPreparedStatement ->
                            namedPreparedStatement.setString(COL_UM_POLICY_ID, policy.getId()));
            policy.setSelectedOrgs(selectedOrgs);
        } catch (DataAccessException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_GET_ORG_POLICY_FAILED.getCode(),
                    ERROR_CODE_GET_ORG_POLICY_FAILED.getMessage(),
                    ERROR_CODE_GET_ORG_POLICY_FAILED.getDescription(), e);
        }
    }

    private void populateResourceSelectedOrgs(ResourceGovernancePolicy policy)
            throws GovernancePolicyMgtServerException {

        NamedJdbcTemplate namedJdbcTemplate = getNewTemplate();
        try {
            List<GovernanceOrgSelected> selectedOrgs = namedJdbcTemplate.executeQuery(
                    SELECT_RESOURCE_GOVERNANCE_ORG_SELECTED_BY_POLICY,
                    (resultSet, rowNum) -> mapGovernanceOrgSelected(resultSet),
                    namedPreparedStatement ->
                            namedPreparedStatement.setString(COL_UM_POLICY_ID, policy.getId()));
            policy.setSelectedOrgs(selectedOrgs);
        } catch (DataAccessException e) {
            throw new GovernancePolicyMgtServerException(ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getCode(),
                    ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getMessage(),
                    ERROR_CODE_GET_RESOURCE_POLICY_FAILED.getDescription(), e);
        }
    }

    private GovernanceOrgSelected mapGovernanceOrgSelected(ResultSet rs) throws SQLException {

        GovernanceOrgSelected selected = new GovernanceOrgSelected();
        selected.setId(rs.getString(COL_UM_ID));
        selected.setPolicyId(rs.getString(COL_UM_POLICY_ID));
        selected.setTargetOrgId(rs.getString(COL_UM_TARGET_ORG_ID));
        selected.setAllowOverride(rs.getBoolean(COL_UM_ALLOW_OVERRIDE));
        return selected;
    }
}
