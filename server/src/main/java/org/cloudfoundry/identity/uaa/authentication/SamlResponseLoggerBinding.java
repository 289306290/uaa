package org.cloudfoundry.identity.uaa.authentication;

import org.opensaml.ws.message.decoder.MessageDecoder;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.security.SecurityPolicyRule;
import org.opensaml.ws.transport.InTransport;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.processor.SAMLBinding;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class SamlResponseLoggerBinding implements SAMLBinding {

    private static final Logger LOGGER = LoggerFactory.getLogger(SamlResponseLoggerBinding.class);

    @Override
    public boolean supports(InTransport transport) {
        HttpServletRequest t = ((HttpServletRequestAdapter) transport).getWrappedRequest();
        String parameterNamesAndSizes = describeParameters(t);
        LOGGER.warn("Malformed SAML response. More details at log level DEBUG.");
        LOGGER.debug("Method: {}, Params (name/size): {}, Content-type: {}, Request-size: {}, X-Vcap-Request-Id: {}",
                t.getMethod(),
                parameterNamesAndSizes,
                t.getContentType(),
                t.getContentLength(),
                "vcap_request_id_abc123");
        return false;
    }

    private String describeParameters(HttpServletRequest t) {
        return t.getParameterMap()
                .entrySet()
                .stream()
                .map(p -> formatParam(p)
                ).collect(Collectors.joining(" "));
    }

    private String formatParam(Map.Entry<String, String[]> p) {
        if (p.getValue()[0] != null)
            return String.format("(%s/%s)", p.getKey(), p.getValue()[0].length());
        else
            return String.format("(%s/0)", p.getKey());
    }

    @Override
    public boolean supports(OutTransport transport) {
        return false;
    }

    @Override
    public MessageDecoder getMessageDecoder() {
        return null;
    }

    @Override
    public MessageEncoder getMessageEncoder() {
        return null;
    }

    @Override
    public String getBindingURI() {
        return null;
    }

    @Override
    public void getSecurityPolicy(List<SecurityPolicyRule> securityPolicy, SAMLMessageContext samlContext) {

    }
}
