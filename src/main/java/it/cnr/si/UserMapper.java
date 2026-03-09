package it.cnr.si;

import it.cnr.si.service.AceService;
import it.cnr.si.service.dto.anagrafica.UserInfoDto;
import it.cnr.si.service.dto.anagrafica.scritture.UtenteDto;
import it.cnr.si.service.dto.anagrafica.simpleweb.SimplePersonaWebDto;
import it.cnr.si.service.dto.anagrafica.simpleweb.SimpleUtenteWebDto;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.*;

public class UserMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    public static final String DATA_CESSAZIONE = "data_cessazione";
    public static final String USERNAME_CNR = "username_cnr";
    public static final String TELEPHONENUMBER = "telephonenumber";
    public static final String TELEFONOCELL = "telefonocell";
    public static final String LIVELLO = "livello";
    public static final String MATRICOLA_CNR = "matricola_cnr";
    public static final String EMAIL_CNR = "email_cnr";
    public static final String EMAIL_ORIGINAL = "email_original";
    public static final String CODICE_FISCALE = "codice_fiscale";
    public static final String IS_CNR_USER = "is_cnr_user";
    public static final String DATAULTIMOCAMBIOPW = "dataultimocambiopw";
    public static final String CNR = "CNR";

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, FullNameMapper.class);
    }

    public static final String PROVIDER_ID = "usermapper";
    public static final String DISPLAY_NAME = "user mapper";
    public static final String HELP_TEXT = "user mapper";

    private static final Logger LOGGER = Logger.getLogger(UserMapper.class);

    private AceService aceService;

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
        if (aceService == null) {
            aceService = new AceService();
        }
        // ldap or spid username
        String username = userSession.getUser().getUsername().toLowerCase();
        String matricola = null;
        String livello = null;
        String email = null;
        String emailOriginal = Optional.ofNullable(userSession.getUser().getAttributes().get("email"))
                .flatMap(list -> list.stream().findFirst())
                .orElse(userSession.getUser().getEmail());
        LOGGER.info("Recuperata email originale: " + emailOriginal);
        String codiceFiscale = null;
        Boolean isCnrUser = Boolean.FALSE;

        try {

            // spid auth
            if(isSpidUsername(username)) {
                try {
                    codiceFiscale = username.substring(6).toUpperCase();
                    final Optional<UtenteDto> utenteByCodiceFiscale = aceService.getUtenteByCodiceFiscale(codiceFiscale);
                    if (utenteByCodiceFiscale.isPresent()) {
                        username = utenteByCodiceFiscale.get().getUsername().toLowerCase();
                        isCnrUser = Boolean.TRUE;   // Utente cnr che entra con spid
                        LOGGER.info("Utente SPID " + username);
                    }
                } catch (Exception e) {
                    LOGGER.info("Utente " + username + " spid non presente in ldap");
                }
            } else {
                isCnrUser = Boolean.TRUE;       // Utente cnr che entra con credenziali cnr
                LOGGER.info("Utente CNR " + username);
            }

            if(isCnrUser) { // Utente cnr che entra con credenziali cnr o spid
                LOGGER.info("Utente " + username + " riconosciuto come CNR");
                try {

                    SimpleUtenteWebDto utente = aceService.getUtente(username);

                    Optional<SimplePersonaWebDto> maybePersona =
                            Optional.ofNullable(utente.getPersona());

                    if(maybePersona.isPresent()) {
                        codiceFiscale = maybePersona.get().getCodiceFiscale();
                        matricola = Optional.ofNullable(maybePersona.get().getMatricola())
                                .map(String::valueOf)
                                .orElse(null);

                        livello = maybePersona.get().getLivello();

                        Optional.ofNullable(maybePersona.get().getDataCessazione())
                                .ifPresent(localDate -> {
                                    token.getOtherClaims().put(DATA_CESSAZIONE, localDate);
                                });
                    }

                    // sovrascrittura campo email nel caso di utenti non strutturati
                    // (campo ldap popolato con "nomail")
                    // setting email
                    email = utente.getEmail();
                    if (!isSpidUsername(username)) {
                        token.setEmail(email);
                        userSession.getUser().getAttributes().put("email", Arrays.asList(email));
                        LOGGER.info("inserita email: " + email + " nel token");
                    }
                } catch (Exception e) {
                    LOGGER.warn("Utente " + username + " non presente in ACE", e);
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
        token.getOtherClaims().put(EMAIL_CNR, email);
        token.getOtherClaims().put(EMAIL_ORIGINAL, emailOriginal);
        token.getOtherClaims().put(CODICE_FISCALE, codiceFiscale);
        token.getOtherClaims().put(DATAULTIMOCAMBIOPW,
                Optional.ofNullable(userSession)
                        .flatMap(userSessionModel -> Optional.ofNullable(userSession.getUser()))
                        .flatMap(userModel -> Optional.ofNullable(userModel.getAttributes().get(DATAULTIMOCAMBIOPW)))
                        .map(strings -> strings.stream().findAny().get())
                        .orElse(null)
        );
        token.getOtherClaims()
                .entrySet()
                .stream()
                .forEach(stringObjectEntry -> LOGGER.info("OtherClaims :: " + stringObjectEntry.getKey() + " -> " + stringObjectEntry.getValue()));
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

    @Override
    public AccessToken transformUserInfoToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        AccessToken accessToken = super.transformUserInfoToken(token, mappingModel, session, userSession, clientSessionCtx);
        String username = Optional.ofNullable(accessToken.getOtherClaims().get(USERNAME_CNR))
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .orElse(userSession.getUser().getUsername());
        if (!isSpidUsername(username) &&
                mappingModel.getConfig()
                        .entrySet()
                        .stream()
                        .filter(stringStringEntry -> stringStringEntry.getKey().equalsIgnoreCase("userinfo.token.claim"))
                        .findAny()
                        .filter(stringStringEntry -> Boolean.valueOf(stringStringEntry.getValue()))
                        .isPresent()
        ) {
            LOGGER.info("User Info for: " + username);
            final UserInfoDto userInfoDto = aceService.getUserInfoDto(username);
            Optional.ofNullable(userSession)
                    .flatMap(userSessionModel -> Optional.ofNullable(userSession.getUser()))
                    .flatMap(userModel -> Optional.ofNullable(userModel.getFirstAttribute(TELEPHONENUMBER)))
                    .ifPresent(s -> {
                        userInfoDto.setTelefono_comunicazioni(s);
                    });
            Optional.ofNullable(userSession)
                    .flatMap(userSessionModel -> Optional.ofNullable(userSession.getUser()))
                    .flatMap(userModel -> Optional.ofNullable(userModel.getFirstAttribute(TELEFONOCELL)))
                    .ifPresent(s -> {
                        userInfoDto.setTelefonocell(s);
                    });
            accessToken.getOtherClaims().put("userInfo", userInfoDto);
            LOGGER.info("User Info value: " + userInfoDto);
            accessToken.getOtherClaims().put("groups", new ArrayList<String>(Arrays.asList(CNR)));
        }
        return accessToken;
    }

}
