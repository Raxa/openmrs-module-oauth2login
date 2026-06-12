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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openmrs.User;
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
public class OAuth2UserInfoAuthenticationScheme extends DaoAuthenticationScheme implements DaemonTokenAware, Serializable {
	
	/**
	 * This bean ends up inside the serialized session payload: OpenmrsFilter stores the UserContext
	 * in the HTTP session on every request, and UserContext holds a reference to its
	 * AuthenticationScheme. With an externalized session store (Redisson/JDBC), session attributes
	 * are serialized on write — a non-serializable scheme turns every request into a 500.
	 * Spring/OpenMRS service handles and the post-processor are runtime wiring, not state: they are
	 * transient and re-acquired after deserialization.
	 */
	private static final long serialVersionUID = 1L;
	
	protected transient Log log = LogFactory.getLog(getClass());
	
	private DaemonToken daemonToken;
	
	private transient AuthenticationPostProcessor postProcessor;
	
	@Autowired
	private transient UserService userService;
	
	@Autowired
	@Qualifier("providerService")
	private transient ProviderService ps;
	
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
	
	private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
		in.defaultReadObject();
		log = LogFactory.getLog(getClass());
		setPostProcessor(new AuthenticationPostProcessor() {
			
			@Override
			public void process(UserInfo userInfo) {
				// no post-processing by default (matches constructor wiring)
			}
		});
	}
	
	private UserService getUserService() {
		if (userService == null) {
			userService = Context.getUserService();
		}
		return userService;
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
		
		User user = getContextDAO().getUserByUsername(credentials.getClientName());
		if (!creds.isServiceAccount()) {
			if (user == null) {
				createUser(creds.getUserInfo());
				// Get the user again after the user has been created
				user = getContextDAO().getUserByUsername(credentials.getClientName());
			} else {
				updateUser(user, creds.getUserInfo());
			}
			
			postProcessor.process(creds.getUserInfo());
		}
		return new BasicAuthenticated(user, credentials.getAuthenticationScheme());
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
			UpdateUserTask task = new UpdateUserTask(getUserService(), userInfo);
			Daemon.runInDaemonThread(task, daemonToken);
		}
		catch (Exception e) {
			throw new ContextAuthenticationException(e.getMessage(), e);
		}
	}
}
