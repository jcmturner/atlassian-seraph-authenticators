package uk.co.jtnet.atlassian.seraph;

import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

import com.atlassian.confluence.user.ConfluenceAuthenticator;
import com.atlassian.seraph.auth.DefaultAuthenticator;

public class RemoteUserTrustAuthenticator extends ConfluenceAuthenticator {
	
	private static final Logger logger = Logger.getLogger(RemoteUserTrustAuthenticator.class);

	@Override
	public Principal getUser(HttpServletRequest request, HttpServletResponse response) {

		if (request.getSession() != null && request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY) != null) {
			// Session already exists for the user
			return (Principal) request.getSession().getAttribute(DefaultAuthenticator.LOGGED_IN_KEY);
		} else {
			// Get the username from the REMOTE_USER header
			String remoteUser = request.getRemoteUser();
			if (remoteUser != null) {
				Principal user = getUser(remoteUser);
				request.getSession().setAttribute(DefaultAuthenticator.LOGGED_IN_KEY, user);
				request.getSession().setAttribute(DefaultAuthenticator.LOGGED_OUT_KEY, null);
				logger.info("User logged in via REMOTE_USER header trust: " + remoteUser);
				return user;
			} else {
				// No REMOTE_USER header
				logger.info("No REMOTE_USER header. User not logged in through REMOTE_USER header trust.");
				return null;
			}
		}
	}
}
