/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
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

package org.wso2.carbon.identity.organization.discovery.service;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.orgdiscovery.OrganizationDiscoveryHandler;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationDiscoveryInput;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationDiscoveryResult;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.organization.config.service.exception.OrganizationConfigException;
import org.wso2.carbon.identity.organization.config.service.model.ConfigProperty;
import org.wso2.carbon.identity.organization.config.service.model.DiscoveryConfig;
import org.wso2.carbon.identity.organization.discovery.service.internal.OrganizationDiscoveryServiceHolder;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementClientException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.BasicOrganization;
import org.wso2.carbon.identity.organization.management.service.model.Organization;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.organization.config.service.constant.OrganizationConfigConstants.ErrorMessages.ERROR_CODE_DISCOVERY_CONFIG_NOT_EXIST;
import static org.wso2.carbon.identity.organization.discovery.service.constant.DiscoveryConstants.ENABLE_CONFIG;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_GETTING_ORGANIZATION_DISCOVERY_CONFIG;

/**
 * Implementation of the Organization Discovery Service.
 */
public class OrganizationDiscoveryServiceImpl implements OrganizationDiscoveryHandler {

    @Override
    public OrganizationDiscoveryResult discoverOrganization(OrganizationDiscoveryInput orgDiscoveryInput,
                                                            AuthenticationContext context)
            throws FrameworkException {

        boolean validDiscoveryParams = validateDiscoveryParameters(orgDiscoveryInput);
        if (!validDiscoveryParams) {
            return OrganizationDiscoveryResult.failure(
                    FrameworkConstants.OrgDiscoveryFailureDetails.VALID_DISCOVERY_PARAMETERS_NOT_FOUND.getCode(),
                    FrameworkConstants.OrgDiscoveryFailureDetails.VALID_DISCOVERY_PARAMETERS_NOT_FOUND.getMessage());
        }
        String appName = context.getServiceProviderName();
        String mainAppResideTenantDomain = context.getTenantDomain();
        String mainAppOrgId;
        try {
            mainAppOrgId = getOrgIdByTenantDomain(mainAppResideTenantDomain);
        } catch (OrganizationManagementException e) {
            throw new FrameworkException("Error while getting organization ID for tenant domain: "
                    + mainAppResideTenantDomain, e);
        }
        if (StringUtils.isNotBlank(orgDiscoveryInput.getOrgId())) {
            String orgId = orgDiscoveryInput.getOrgId();
            Optional<BasicOrganization> organization = getBasicOrganizationDetails(orgId);
            if (!organization.isPresent()) {
                return OrganizationDiscoveryResult.failure(
                        FrameworkConstants.OrgDiscoveryFailureDetails.ORGANIZATION_NOT_FOUND.getCode(),
                        FrameworkConstants.OrgDiscoveryFailureDetails.ORGANIZATION_NOT_FOUND.getMessage());
            }
            Optional<ServiceProvider> sharedApplication = getSharedApplication(appName, mainAppOrgId,
                    orgDiscoveryInput.getOrgId());
            if (!sharedApplication.isPresent()) {
                throw new OrganizationDiscoveryClientException(
                        OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_APPLICATION_NOT_SHARED.getMessage(),
                        OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_APPLICATION_NOT_SHARED.getDescription(),
                        OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_APPLICATION_NOT_SHARED.getCode()
                );
            }
            buildOrganizationDiscoveryResult(true, organization, sharedApplication.get(), null);
        } else if (StringUtils.isNotBlank(orgDiscoveryInput.getLoginHint())) {
            String loginHint = orgDiscoveryInput.getLoginHint();
            String orgDiscoveryType = StringUtils.isNotBlank(orgDiscoveryInput.getOrgDiscoveryType()) ?
                    orgDiscoveryInput.getOrgDiscoveryType() : "emailDomain";

        } else {

        }
    }

    private boolean validateDiscoveryParameters(OrganizationDiscoveryInput orgDiscoveryInput) {

        return StringUtils.isNotBlank(orgDiscoveryInput.getOrgId()) ||
                StringUtils.isNotBlank(orgDiscoveryInput.getLoginHint()) ||
                StringUtils.isNotBlank(orgDiscoveryInput.getOrgHandle()) ||
                StringUtils.isNotBlank(orgDiscoveryInput.getOrgName());
    }

    private String getOrgIdByTenantDomain(String tenantDomain) throws OrganizationManagementException {

        return OrganizationDiscoveryServiceHolder.getInstance().getOrganizationManager()
                .resolveOrganizationId(tenantDomain);
    }

    private Optional<ServiceProvider> getSharedApplication(String appName, String appResideOrgId, String sharedOrgId)
            throws OrganizationDiscoveryException {

        ServiceProvider sharedApplication;
        try {
            sharedApplication = OrganizationDiscoveryServiceHolder.getInstance().getOrgApplicationManager()
                    .resolveSharedApplication(appName, appResideOrgId, sharedOrgId);
        } catch (OrganizationManagementException e) {
            if (e instanceof OrganizationManagementClientException) {
                if (OrganizationManagementConstants.ErrorMessages.ERROR_CODE_APPLICATION_NOT_SHARED.getCode()
                        .equals(e.getErrorCode())) {
                    throw new OrganizationDiscoveryClientException(
                            OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_APPLICATION_NOT_SHARED.getMessage(),
                            OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_APPLICATION_NOT_SHARED
                                    .getDescription(),
                            OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_APPLICATION_NOT_SHARED.getCode()
                    );
                } else {
                    throw new OrganizationDiscoveryServerException(
                            OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getMessage(),
                            OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getDescription(),
                            OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(),
                            e);
                }
            } else {
                throw new OrganizationDiscoveryServerException(
                        OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getMessage(),
                        OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getDescription(),
                        OrganizationDiscoveryConstants.ErrorMessages.ERROR_CODE_UNEXPECTED.getCode(),
                        e);
            }
        }
        return Optional.of(sharedApplication);
    }

    private Optional<BasicOrganization> getBasicOrganizationDetails(String orgId) throws FrameworkException {

        Organization organization;
        try {
            organization = OrganizationDiscoveryServiceHolder.getInstance()
                    .getOrganizationManager().getOrganization(orgId, false, false);
        } catch (OrganizationManagementException e) {
            if (e instanceof OrganizationManagementClientException &&
                    OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_ORGANIZATION.getCode()
                            .equals(e.getErrorCode())) {
                return Optional.empty();
            } else {
                throw new FrameworkException("Error while retrieving organization details for organization ID: "
                        + orgId, e);
            }
        }
        BasicOrganization basicOrganization = new BasicOrganization();
        basicOrganization.setId(orgId);
        basicOrganization.setName(organization.getName());
        basicOrganization.setOrganizationHandle(organization.getOrganizationHandle());
        return Optional.of(basicOrganization);
    }

    private boolean isOrganizationDiscoveryTypeEnabled(String discoveryType)
            throws AuthenticationFailedException {

        try {
            DiscoveryConfig discoveryConfig = OrganizationDiscoveryServiceHolder.getInstance().getOrganizationConfigManager().getDiscoveryConfiguration();
            Map<String, AttributeBasedOrganizationDiscoveryHandler> discoveryHandlers =
                    OrganizationDiscoveryServiceHolder.getInstance().getAttributeBasedOrganizationDiscoveryHandlers();

            List<ConfigProperty> configProperties = discoveryConfig.getConfigProperties();
            for (ConfigProperty configProperty : configProperties) {
                String type = configProperty.getKey().split(ENABLE_CONFIG)[0];
                if (discoveryType.equals(type) && discoveryHandlers.get(type) != null &&
                        Boolean.parseBoolean(configProperty.getValue())) {
                    return true;
                }
            }
        } catch (OrganizationConfigException e) {
            if (ERROR_CODE_DISCOVERY_CONFIG_NOT_EXIST.getCode().equals(e.getErrorCode())) {
                return false;
            }
            throw handleAuthFailures(ERROR_CODE_ERROR_GETTING_ORGANIZATION_DISCOVERY_CONFIG, e);
        }
        return false;
    }
}
