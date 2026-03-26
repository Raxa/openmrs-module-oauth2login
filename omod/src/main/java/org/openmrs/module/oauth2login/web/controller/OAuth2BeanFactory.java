/*
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.oauth2login.web.controller;

import java.io.IOException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.module.oauth2login.PropertyUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Minimal bean factory — only registers oauth2.properties for the OAuth2ServiceAccountFilter
 * (Bearer token validation). Spring Security OAuth2 client is removed to avoid Hibernate
 * CacheManager conflicts with Raxa/Bahmni.
 */
@Configuration
public class OAuth2BeanFactory {
	
	protected static final Log LOG = LogFactory.getLog(OAuth2BeanFactory.class);
	
	@Bean(name = "oauth2.properties")
	public Properties getOAuth2Properties() throws IOException {
		return PropertyUtils.getOAuth2Properties();
	}
	
	@Bean(name = "oauth2.userInfoUri")
	public String getOAuth2UserInfoUri() throws IOException {
		Properties props = getOAuth2Properties();
		return props.getProperty("userInfoUri");
	}
}
