/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.organization.management.application.model.operation;

import org.wso2.carbon.identity.organization.resource.sharing.policy.management.constant.PolicyEnum;

/**
 * This class represents the selective application share.
 */
public class SelectiveShareApplicationOperation extends ApplicationShareOperation {

        private final String organizationId;

        public SelectiveShareApplicationOperation(String organizationId, PolicyEnum policy,
                                                  ApplicationShareRolePolicy applicationShareRolePolicy) {

            super(policy, applicationShareRolePolicy);
            this.organizationId = organizationId;
        }

        public String getOrganizationId() {

            return organizationId;
        }
    }
