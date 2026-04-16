/**
 * This Source Code Form is subject to the terms of the Mozilla Public License,
 * v. 2.0. If a copy of the MPL was not distributed with this file, You can
 * obtain one at http://mozilla.org/MPL/2.0/. OpenMRS is also distributed under
 * the terms of the Healthcare Disclaimer located at http://openmrs.org/license.
 *
 * Copyright (C) OpenMRS Inc. OpenMRS is a registered trademark and the OpenMRS
 * graphic logo is a trademark of OpenMRS Inc.
 */
package org.openmrs.module.oauth2login.authscheme;

import static org.openmrs.module.oauth2login.OAuth2LoginConstants.AUTH_SCHEME_COMPONENT;

import java.util.List;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
import org.openmrs.api.AdministrationService;
import org.openmrs.api.ProviderService;
import org.openmrs.api.UserService;
import org.openmrs.api.context.Authenticated;
import org.openmrs.api.context.BasicAuthenticated;
import org.openmrs.api.context.Context;
import org.openmrs.api.context.ContextAuthenticationException;
import org.openmrs.api.context.Credentials;
import org.openmrs.api.context.Daemon;
import org.openmrs.api.context.DaoAuthenticationScheme;
import org.openmrs.module.DaemonToken;
import org.openmrs.module.DaemonTokenAware;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * A scheme that authenticates with OpenMRS based on the 'username'.
 */
@Transactional
@Component(AUTH_SCHEME_COMPONENT)
public class OAuth2UserInfoAuthenticationScheme extends DaoAuthenticationScheme implements DaemonTokenAware {
	
	protected Log log = LogFactory.getLog(getClass());
	
	private DaemonToken daemonToken;
	
	private AuthenticationPostProcessor postProcessor;
	
	@Autowired
	private UserService userService;
	
	@Autowired
	@Qualifier("providerService")
	private ProviderService ps;
	
	public void setDaemonToken(DaemonToken daemonToken) {
		this.daemonToken = daemonToken;
	}
	
	public void setPostProcessor(AuthenticationPostProcessor postProcessor) {
		this.postProcessor = postProcessor;
	}
	
	public OAuth2UserInfoAuthenticationScheme() {
		setPostProcessor(new AuthenticationPostProcessor() {
			
			@Override
			public void process(UserInfo userInfo) {
				// no post-processing by default
			}
		});
	}
	
	@Override
	public Authenticated authenticate(Credentials credentials) throws ContextAuthenticationException {
		
		// For non-OAuth2 credentials (e.g. UsernamePasswordCredentials from Basic Auth),
		// fall back to DAO-based username/password authentication for backward compatibility.
		if (!(credentials instanceof OAuth2TokenCredentials)) {
			if (credentials instanceof org.openmrs.api.context.UsernamePasswordCredentials) {
				org.openmrs.api.context.UsernamePasswordCredentials upCreds = (org.openmrs.api.context.UsernamePasswordCredentials) credentials;
				User user = getContextDAO().authenticate(upCreds.getUsername(), upCreds.getPassword());
				return new BasicAuthenticated(user, credentials.getAuthenticationScheme());
			}
			throw new ContextAuthenticationException("Unsupported credential type: " + credentials.getClass().getName());
		}
		
		OAuth2TokenCredentials creds = (OAuth2TokenCredentials) credentials;
		
		// Step 1: standard lookup by preferred_username
		User user = getContextDAO().getUserByUsername(credentials.getClientName());
		
		if (!creds.isServiceAccount()) {
			if (user == null) {
				user = findExistingUserByEmail(credentials.getClientName(), creds.getUserInfo());
				if (user != null) {
					updateUser(user, creds.getUserInfo());
					postProcessor.process(creds.getUserInfo());
					return new BasicAuthenticated(user, credentials.getAuthenticationScheme());
				}
				// No existing user found by any method — create a new account.
				createUser(creds.getUserInfo());
				user = getContextDAO().getUserByUsername(credentials.getClientName());
			} else {
				updateUser(user, creds.getUserInfo());
			}
			
			postProcessor.process(creds.getUserInfo());
		}
		return new BasicAuthenticated(user, credentials.getAuthenticationScheme());
	}
	
	/**
	 * Tries to find an existing OpenMRS user whose email matches the JWT email claim. Lookup chain
	 * (stops at first match): 1. users.email / username column — via getUserByUsernameOrEmail() 2.
	 * person_attribute "Email" value — covers all accounts created before users.email was populated
	 * (most existing users) Logs a WARN on every match so admins can align Keycloak
	 * preferred_username over time.
	 * 
	 * @param preferredUsername the Keycloak preferred_username that failed getUserByUsername()
	 * @param userInfo JWT claims object
	 * @return matched User, or null if none found
	 */
	private User findExistingUserByEmail(String preferredUsername, UserInfo userInfo) {
		String email = userInfo.getString(UserInfo.PROP_EMAIL);
		if (email == null || email.isEmpty()) {
			return null;
		}
		
		// --- Step 2: users.email / username column ---
		// getUserByUsernameOrEmail searches both username and email fields.
		User byEmail = userService.getUserByUsernameOrEmail(email);
		if (byEmail != null) {
			log.warn("OAuth2 login: username '" + preferredUsername + "' not found; matched existing user by users.email='"
			        + email + "' (OpenMRS username: '" + byEmail.getUsername()
			        + "'). Update Keycloak preferred_username to fix permanently.");
			return byEmail;
		}
		
		// --- Step 3: person_attribute "Email" ---
		// Covers all existing users whose email is only in person_attribute
		// and was never copied to users.email (the common case for pre-OAuth2 accounts).
		try {
			User byPersonAttr = findUserByPersonAttributeEmail(email, preferredUsername);
			if (byPersonAttr != null) {
				return byPersonAttr;
			}
		}
		catch (Exception e) {
			log.error(
			    "OAuth2 login: error during person_attribute email fallback for '" + preferredUsername + "': "
			            + e.getMessage(), e);
		}
		
		return null;
	}
	
	/**
	 * Queries the person_attribute table for an exact email match and returns the associated User.
	 * Uses AdministrationService.executeSQL() since PersonService.getPersonAttributesByValue() is
	 * not available in OpenMRS 2.3.x.
	 */
	private User findUserByPersonAttributeEmail(String email, String preferredUsername) {
		// Sanitize email to prevent SQL injection (email comes from a verified JWT,
		// but we escape single quotes as an extra safety measure).
		String safeEmail = email.replace("'", "''");
		
		String sql = "SELECT u.user_id FROM users u " + "JOIN person_attribute pa ON pa.person_id = u.person_id "
		        + "JOIN person_attribute_type pat ON pat.person_attribute_type_id = pa.person_attribute_type_id "
		        + "WHERE LOWER(pa.value) = LOWER('" + safeEmail + "') " + "AND pat.name = 'Email' "
		        + "AND pa.voided = false " + "AND u.retired = false " + "LIMIT 1";
		
		AdministrationService adminService = Context.getAdministrationService();
		List<List<Object>> results = adminService.executeSQL(sql, true);
		
		if (results != null && !results.isEmpty()) {
			List<Object> row = results.get(0);
			if (row != null && !row.isEmpty() && row.get(0) != null) {
				Integer userId = Integer.valueOf(row.get(0).toString());
				User matched = userService.getUser(userId);
				if (matched != null) {
					log.warn("OAuth2 login: username '" + preferredUsername
					        + "' not found; matched existing user by person_attribute Email='" + email
					        + "' (OpenMRS username: '" + matched.getUsername()
					        + "'). Update Keycloak preferred_username to fix permanently.");
					return matched;
				}
			}
		}
		
		return null;
	}
	
	private void createUser(UserInfo userInfo) throws ContextAuthenticationException {
		try {
			User user = userInfo.getOpenmrsUser("n/a");
			String password = RandomStringUtils.random(100, true, true);
			getContextDAO().createUser(user, password, userInfo.getRoleNames());
		}
		catch (Exception e) {
			throw new ContextAuthenticationException(e.getMessage(), e);
		}
	}
	
	private void updateUser(User user, UserInfo userInfo) {
		try {
			UpdateUserTask task = new UpdateUserTask(userService, userInfo);
			Daemon.runInDaemonThread(task, daemonToken);
		}
		catch (Exception e) {
			throw new ContextAuthenticationException(e.getMessage(), e);
		}
	}
}
