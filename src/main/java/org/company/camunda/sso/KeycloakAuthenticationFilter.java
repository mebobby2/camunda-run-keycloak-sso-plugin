package org.company.camunda.sso;

import static org.camunda.bpm.engine.authorization.Permissions.ACCESS;
import static org.camunda.bpm.engine.authorization.Resources.APPLICATION;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.camunda.bpm.cockpit.Cockpit;
import org.camunda.bpm.engine.AuthorizationService;
import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.identity.Group;
import org.camunda.bpm.engine.rest.spi.ProcessEngineProvider;
import org.camunda.bpm.webapp.impl.security.SecurityActions;
import org.camunda.bpm.webapp.impl.security.SecurityActions.SecurityAction;
import org.camunda.bpm.webapp.impl.security.auth.Authentication;
import org.camunda.bpm.webapp.impl.security.auth.Authentications;
import org.camunda.bpm.webapp.impl.security.auth.UserAuthentication;
import java.util.logging.Logger;

public class KeycloakAuthenticationFilter implements Filter {

    private static final String[] APPS = new String[] { "cockpit", "tasklist" };
    private static final String APP_MARK = "/app/";
    private static final String SSO_HEADER_FIELD = "SsoUserHeader";
    private static final String CAMUNDA_ADMIN_GROUP = "camunda-admin";

    private static final Logger logger = Logger.getLogger(KeycloakAuthenticationFilter.class.getName());

    public void init(FilterConfig filterConfig) throws ServletException {
    }

    protected ProcessEngine lookupProcessEngine(String engineName) {

        ServiceLoader<ProcessEngineProvider> serviceLoader = ServiceLoader.load(ProcessEngineProvider.class);
        Iterator<ProcessEngineProvider> iterator = serviceLoader.iterator();
        if (iterator.hasNext()) {
            ProcessEngineProvider provider = iterator.next();
            return provider.getProcessEngine(engineName);

        }
        return null;
    }

    protected boolean isAuthorizedForApp(AuthorizationService authorizationService, String username, List<String> groupIds, String application) {
        return authorizationService.isUserAuthorized(username, groupIds, ACCESS, APPLICATION, application);
    }

    protected void setKnownPrinicipal(final ServletRequest request, Authentications authentications) {
        final HttpServletRequest req = (HttpServletRequest) request;

        // Get User from OpenAM SSO Header
        String username = req.getHeader(SSO_HEADER_FIELD);
        logger.info(SSO_HEADER_FIELD+" : "+username);

        boolean isAdmin = false;

        if (username != null && !username.isEmpty()) {
            for (Authentication aut : authentications.getAuthentications()) {
                if (aut.getName() == username) {
                    // already in the list - nothing to do
                    return;
                }
            }
            String url = req.getRequestURL().toString();
            String[] appInfo = getAppInfo(url);

            if (appInfo != null) {
                String engineName = getEngineName(appInfo);
                String appName = getAppName(appInfo);

                final ProcessEngine processEngine = lookupProcessEngine(engineName);
                if (processEngine != null) {
                    // throw new InvalidRequestException(Status.BAD_REQUEST,
                    // "Process engine with name "+engineName+" does not exist");
                    // get user's groups
                    final List<Group> groupList = processEngine.getIdentityService().createGroupQuery().groupMember(username).list();
                    // transform into array of strings:
                    List<String> groupIds = new ArrayList<String>();
                    for (Group group : groupList) {
                        groupIds.add(group.getId());
                        logger.info("Adding group : "+group.getId());
                        if(group.getId().equals(CAMUNDA_ADMIN_GROUP)) {
                        	isAdmin = true;
                        	logger.info("Current user is in ADMIN group");
                        }
                    }

                    // check user's app authorizations
                    AuthorizationService authorizationService = processEngine.getAuthorizationService();
                    HashSet<String> authorizedApps = new HashSet<String>();
                    for (String application : APPS) {
                        if (isAuthorizedForApp(authorizationService, username, groupIds, application)) {
                            authorizedApps.add(application);
                            logger.info("IsAuthorizedForApp : "+application);
                        }
                    }
                    if(isAdmin) authorizedApps.add("admin");
                    if (authorizedApps.contains(appName)) {
                        // UserAuthentication newAuthentication = new UserAuthentication(username, groupIds, engineName, authorizedApps);
                        UserAuthentication newAuthentication = new UserAuthentication(username, engineName);
                        authentications.addAuthentication(newAuthentication);
                    }
                }
            }
        }
    }

    private String getAppName(String[] appInfo) {
        return appInfo[0];
    }

    private String getEngineName(String[] appInfo) {
        return appInfo[1];
    }

    private String[] getAppInfo(String url) {
        String[] appInfo = null;
        if (url.endsWith("/")) {
            int index = url.indexOf(APP_MARK);
            if (index >= 0) {
                String apps = url.substring(index + APP_MARK.length(), url.length() - 1);
                String[] aa = apps.split("/");
                if (aa.length == 2) {
                    appInfo = aa;
                }
            }
        }
        return appInfo;
    }

    private boolean isApp(String url) {
        return url.contains("/app/");
    }

    public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest req = (HttpServletRequest) request;

        // get authentication from session
        Authentications authentications = Authentications.getFromSession(req.getSession());
        setKnownPrinicipal(request, authentications);
        Authentications.setCurrent(authentications);
        try {

            SecurityActions.runWithAuthentications(new SecurityAction<Void>() {
                public Void execute() {
                    try {
                        chain.doFilter(request, response);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    return null;
                }
            }, authentications);
        } finally {
            Authentications.clearCurrent();
            Authentications.updateSession(req.getSession(), authentications);
        }

    }

    protected void clearProcessEngineAuthentications(Authentications authentications) {
        for (Authentication authentication : authentications.getAuthentications()) {
            ProcessEngine processEngine = Cockpit.getProcessEngine(authentication.getProcessEngineName());
            if (processEngine != null) {
                processEngine.getIdentityService().clearAuthentication();
            }
        }
    }

    public void destroy() {

    }
}
