package org.apache.catalina.authenticator.jaspic.provider.modules;

import java.util.Map;
import java.util.regex.Pattern;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static java.lang.Boolean.TRUE;

import org.apache.catalina.Context;
import org.apache.catalina.authenticator.Constants;

/**
 * A SPNEGO authenticator that uses the SPNEGO/Kerberos support built in to Java
 * 6. Successful Kerberos authentication depends on the correct configuration of
 * multiple components. If the configuration is invalid, the error messages are
 * often cryptic although a Google search will usually point you in the right
 * direction.
 */
public class SpnegoAuthModule extends TomcatAuthModule {
    private Class<?>[] supportedMessageTypes = new Class[] { HttpServletRequest.class,
            HttpServletResponse.class };
    
    private String loginConfigName = Constants.DEFAULT_LOGIN_MODULE_NAME;
    private boolean storeDelegatedCredential = true;
    private Pattern noKeepAliveUserAgents = null;
    private boolean applyJava8u40Fix = true;

    @Override
    public Class<?>[] getSupportedMessageTypes() {
        return supportedMessageTypes;
    }


    @Override
    public void initializeModule(MessagePolicy requestPolicy, MessagePolicy responsePolicy,
            CallbackHandler handler, Map<String, String> options) throws AuthException {
        this.loginConfigName = options.getOrDefault("loginConfigName", Constants.DEFAULT_LOGIN_MODULE_NAME);
        this.storeDelegatedCredential = Boolean.parseBoolean(options.getOrDefault("storeDelegatedCredential", TRUE.toString()));
        this.noKeepAliveUserAgents = compilePattern(options.get("noKeepAliveUserAgents"));
        this.applyJava8u40Fix = Boolean.parseBoolean(options.getOrDefault("applyJava8u40Fix", TRUE.toString()));
    }
    
    private Pattern compilePattern(String noKeepAliveUserAgents) {
        if (noKeepAliveUserAgents == null || noKeepAliveUserAgents.length() == 0) {
            return null;
        }
        return Pattern.compile(noKeepAliveUserAgents);
    }


    public SpnegoAuthModule(Context context) {
        super(context);
    }


    @Override
    public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject,
            Subject serviceSubject) throws AuthException {
        return null;
    }


    @Override
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject)
            throws AuthException {
        return null;
    }


    @Override
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {

    }

}
