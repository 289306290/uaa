package org.cloudfoundry.identity.uaa.scim.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.authentication.AnonymousAuthenticationToken;

import static java.util.Optional.ofNullable;

public class UserModifiedEvent extends AbstractUaaEvent {

    private static final long serialVersionUID = 8139998613071093676L;
    private final ScimUser scimUser;
    private final AuditEventType eventType;

    private UserModifiedEvent(
            final ScimUser scimUser,
            final AuditEventType eventType,
            final String zoneId) {
        super(getContextAuthentication(), zoneId);
        this.scimUser = scimUser;
        this.eventType = eventType;
    }

    static UserModifiedEvent userCreated(final ScimUser scimUser, final String zoneId) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserCreatedEvent, zoneId);
    }

    static UserModifiedEvent userModified(final ScimUser scimUser, final String zoneId) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserModifiedEvent, zoneId);
    }

    static UserModifiedEvent userDeleted(final ScimUser scimUser, final String zoneId) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserDeletedEvent, zoneId);
    }

    static UserModifiedEvent userVerified(final ScimUser scimUser, final String zoneId) {
        return new UserModifiedEvent(scimUser, AuditEventType.UserVerifiedEvent, zoneId);
    }

    public static UserModifiedEvent emailChanged(final ScimUser scimUser, final String zoneId) {
        return new UserModifiedEvent(scimUser, AuditEventType.EmailChangedEvent, zoneId);
    }

    @Override
    public AuditEvent getAuditEvent() {
        String data = JsonUtils.writeValueAsString(buildDetails());
        return createAuditRecord(
                scimUser.getId(),
                eventType,
                getOrigin(getAuthentication()),
                data);
    }


    /**
     * TODO: use SecurityContextAccessor
     */
    private String[] buildDetails() {
        if (AuditEventType.UserCreatedEvent.equals(this.eventType)) {

            // Not authenticated, e.g. when saml login creates a shadow user
            if (!getContextAuthentication().isAuthenticated() || getContextAuthentication() instanceof AnonymousAuthenticationToken) {
                return new String[]{
                        "user_id=" + scimUser.getId(),
                        "username=" + scimUser.getUserName(),
                        "user_origin=" + scimUser.getOrigin()
                };
            }

            // Authenticated as a user
            if (getContextAuthentication().getPrincipal() instanceof UaaPrincipal) {
                UaaPrincipal uaaPrincipal = (UaaPrincipal) getContextAuthentication().getPrincipal();

                return new String[]{
                        "user_id=" + scimUser.getId(),
                        "username=" + scimUser.getUserName(),
                        "user_origin=" + scimUser.getOrigin(),
                        "performed_by=" + uaaPrincipal.getId() + "|" + uaaPrincipal.getName()
                };
            }

            String zoneId = "<unknown>";

            if (getContextAuthentication() instanceof UaaOauth2Authentication) {
                final String tokenValue = ((UaaOauth2Authentication) getContextAuthentication()).getTokenValue();
                final Claims claims = JsonUtils.readValue(JwtHelper.decode(tokenValue).getClaims(), Claims.class);
                zoneId = ofNullable(claims).map(Claims::getZid).orElse("");
            }

            // Authenticated as a client
            return new String[]{
                    "user_id=" + scimUser.getId(),
                    "username=" + scimUser.getUserName(),
                    "user_origin=" + scimUser.getOrigin(),
                    "performed_by=" + zoneId + "|" + getContextAuthentication().getPrincipal()
            };
        } else if (AuditEventType.UserDeletedEvent.equals(this.eventType)) {

            // Authenticated as a user
            if (getContextAuthentication().getPrincipal() instanceof UaaPrincipal) {
                UaaPrincipal uaaPrincipal = (UaaPrincipal) getContextAuthentication().getPrincipal();

                return new String[]{
                        "user_id=" + scimUser.getId(),
                        "username=" + scimUser.getUserName(),
                        "user_origin=" + scimUser.getOrigin(),
                        "deleted_by_user_id=" + uaaPrincipal.getId(),
                        "deleted_by_username=" + uaaPrincipal.getName()
                };
            }

            // Authenticated as a client
            return new String[]{
                    "user_id=" + scimUser.getId(),
                    "username=" + scimUser.getUserName(),
                    "user_origin=" + scimUser.getOrigin(),
                    "deleted_by_client_id=" + getContextAuthentication().getPrincipal()
            };
        }
        return new String[]{
                "user_id=" + scimUser.getId(),
                "username=" + scimUser.getUserName()
        };
    }

    public String getUserId() {
        return scimUser.getId();
    }

    public String getUsername() {
        return scimUser.getUserName();
    }

    public String getEmail() {
        return scimUser.getPrimaryEmail();
    }

}
