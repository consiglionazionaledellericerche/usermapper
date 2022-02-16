package it.cnr.si;

import it.cnr.si.service.AceService;
import it.cnr.si.service.dto.anagrafica.letture.PersonaWebDto;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.*;

public class UserMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    public static final String DATA_CESSAZIONE = "data_cessazione";
    public static final String USERNAME_CNR = "username_cnr";
    public static final String LIVELLO = "livello";
    public static final String MATRICOLA_CNR = "matricola_cnr";
    public static final String IS_CNR_USER = "is_cnr_user";

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, FullNameMapper.class);
    }

    public static final String PROVIDER_ID = "usermapper";
    public static final String DISPLAY_NAME = "user mapper";
    public static final String HELP_TEXT = "user mapper";

    private static final Logger LOGGER = Logger.getLogger(UserMapper.class);

    private AceService aceService = new AceService();

    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return DISPLAY_NAME;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {

        // ldap or spid username
        String username = userSession.getUser().getUsername().toLowerCase();
        String matricola = null;
        String livello = null;
        Boolean isCnrUser = Boolean.FALSE;

        try {

            // spid auth
            if(isSpidUsername(username)) {
                try {
                    String codiceFiscale = username.substring(6).toUpperCase();
                    username = aceService.getUtenteByCodiceFiscale(codiceFiscale).getUsername().toLowerCase();
                    isCnrUser = Boolean.TRUE;   // Utente cnr che entra con spid
                } catch (Exception e) {
                    LOGGER.info("Utente " + username + " spid non presente in ldap");
                }
            } else {
                isCnrUser = Boolean.TRUE;       // Utente cnr che entra con credenziali cnr
            }

            if(isCnrUser) { // Utente cnr che entra con credenziali cnr o spid
                try {
                    Integer id = aceService.getPersonaByUsername(username).getId();
                    final PersonaWebDto personaById = aceService.getPersonaById(id);
                    matricola = Integer.toString(personaById.getMatricola());
                    livello = personaById.getLivello();

                    // sovrascrittura campo email nel caso di utenti non strutturati
                    // (campo ldap popolato con "nomail")
                    token.setEmail(aceService.getUtente(username).getEmail());
                    Optional.ofNullable(personaById.getDataCessazione())
                            .ifPresent(localDate -> {
                                token.getOtherClaims().put(DATA_CESSAZIONE, localDate);
                            });
                } catch (Exception e) {
                    LOGGER.info("utente " + username + " spid non presente in ldap");
                }
            }
            LOGGER.info(username);

        } catch (Exception e) {
            LOGGER.error(e);
        }

        token.getOtherClaims().put(USERNAME_CNR, username);
        token.getOtherClaims().put(LIVELLO, livello);
        token.getOtherClaims().put(MATRICOLA_CNR, matricola);
        token.getOtherClaims().put(IS_CNR_USER, isCnrUser);

    }

    private boolean isSpidUsername(String username) {
        return username.toUpperCase().startsWith("TINIT");
    }

    public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<>();
        if (accessToken) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        if (idToken) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        if (userInfo) config.put(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, "true");
        mapper.setConfig(config);
        return mapper;
    }

}
