package example.micronaut.providers

import groovy.transform.CompileDynamic
import groovy.transform.CompileStatic
import io.micronaut.context.annotation.Value
import io.micronaut.security.authentication.AuthenticationFailed
import io.micronaut.security.authentication.AuthenticationProvider
import io.micronaut.security.authentication.AuthenticationRequest
import io.micronaut.security.authentication.AuthenticationResponse
import io.micronaut.security.authentication.UserDetails
import io.reactivex.Flowable
import org.ldaptive.ConnectionConfig
import org.ldaptive.Credential
import org.ldaptive.DefaultConnectionFactory
import org.ldaptive.auth.Authenticator
import org.ldaptive.auth.FormatDnResolver
import org.ldaptive.auth.PooledBindAuthenticationHandler
import org.ldaptive.pool.BlockingConnectionPool
import org.ldaptive.pool.IdlePruneStrategy
import org.ldaptive.pool.PoolConfig
import org.ldaptive.pool.PooledConnectionFactory
import org.ldaptive.pool.SearchValidator
import org.reactivestreams.Publisher

import javax.annotation.PostConstruct
import javax.inject.Singleton
import java.time.Duration

@CompileStatic
@Singleton // <1>
class LdapService implements AuthenticationProvider { // <2>

    protected final String ldapServer
    protected final Integer ldapPort
    protected final String baseDn
    private Authenticator ldaptiveAuthenticator

    LdapService(@Value('${ldap.server}') String ldapServer, // <3>
                @Value('${ldap.port}') Integer port,
                @Value('${ldap.basedn}') String baseDn) {
        this.ldapServer = ldapServer
        this.ldapPort = port
        this.baseDn = baseDn
    }

    @PostConstruct // <4>
    void initialize() {
        FormatDnResolver dnResolver = new FormatDnResolver()
        dnResolver.setFormat(baseDn)
        ConnectionConfig connectionConfig = new ConnectionConfig()
        connectionConfig.with {
            setConnectTimeout(Duration.ofSeconds(500))
            setResponseTimeout(Duration.ofSeconds(1000))
            setLdapUrl("ldap://" + ldapServer + ":" + ldapPort)
        }
        DefaultConnectionFactory connectionFactory = new DefaultConnectionFactory()
        connectionFactory.setConnectionConfig(connectionConfig)
        PoolConfig poolConfig = new PoolConfig()
        poolConfig.with {
            setMinPoolSize(1)
            setMaxPoolSize(2)
            setValidateOnCheckOut(true)
            setValidateOnCheckIn(true)
            setValidatePeriodically(false)
        }
        SearchValidator searchValidator = new SearchValidator()
        IdlePruneStrategy pruneStrategy = new IdlePruneStrategy()
        BlockingConnectionPool connectionPool = new BlockingConnectionPool()
        connectionPool.with {
            setPoolConfig(poolConfig)
            setBlockWaitTime(Duration.ofSeconds(1000))
            setValidator(searchValidator)
            setPruneStrategy(pruneStrategy)
            setConnectionFactory(connectionFactory)
            initialize()
        }
        PooledConnectionFactory pooledConnectionFactory = new PooledConnectionFactory()
        pooledConnectionFactory.setConnectionPool(connectionPool)
        PooledBindAuthenticationHandler handler = new PooledBindAuthenticationHandler()
        handler.setConnectionFactory(pooledConnectionFactory)
        ldaptiveAuthenticator = new Authenticator()
        ldaptiveAuthenticator.setDnResolver(dnResolver)
        ldaptiveAuthenticator.setAuthenticationHandler(handler)
    }

    @CompileDynamic
    @Override
    Publisher<AuthenticationResponse> authenticate(AuthenticationRequest authenticationRequest) {
        final String username = authenticationRequest.getIdentity() as String
        final String password = authenticationRequest.getSecret() as String
        Credential credential = new Credential(password)
        org.ldaptive.auth.AuthenticationRequest req = new org.ldaptive.auth.AuthenticationRequest(username, credential)
        org.ldaptive.auth.AuthenticationResponse response = ldaptiveAuthenticator.authenticate(req)
        Flowable.just(response.getResult() ? new UserDetails(username, []) // <5>
                : new AuthenticationFailed())
    }
}
