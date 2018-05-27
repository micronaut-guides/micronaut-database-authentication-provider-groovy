package example.micronaut

import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.micronaut.security.token.jwt.render.AccessRefreshToken
import io.micronaut.security.token.jwt.validator.JwtTokenValidator
import io.micronaut.security.token.validator.TokenValidator
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class LoginLdapSpec extends Specification {

    @Shared
    @AutoCleanup // <1>
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer) // <2>

    @Shared
    @AutoCleanup // <1>
    HttpClient client = HttpClient.create(embeddedServer.URL) // <3>

    void '/login with valid credentials returns 200 and access token and refresh token'() {
        when:
        HttpRequest request = HttpRequest.create(HttpMethod.POST, '/login')
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .body(new UsernamePasswordCredentials('euler', 'password')) // <4>
        HttpResponse<AccessRefreshToken> rsp = client.toBlocking().exchange(request, AccessRefreshToken)

        then:
        rsp.status.code == 200
        rsp.body.isPresent()
        rsp.body.get().accessToken
        rsp.body.get().refreshToken
    }

    void '/login with invalid credentials returns UNAUTHORIZED'() {
        when:
        HttpRequest request = HttpRequest.create(HttpMethod.POST, '/login')
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .body(new UsernamePasswordCredentials('euler', 'bogus'))  // <4>
        client.toBlocking().exchange(request)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status.code == 401 // <5>
    }

    void 'access token contains expiration date'() {
        when:
        HttpRequest request = HttpRequest.create(HttpMethod.POST, '/login')
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .body(new UsernamePasswordCredentials('euler', 'password')) // <4>
                HttpResponse<AccessRefreshToken> rsp = client.toBlocking().exchange(request, AccessRefreshToken)

        then:
        rsp.status.code == 200
        rsp.body.isPresent()

        when:
        String accessToken = rsp.body.get().accessToken

        then:
        accessToken

        when:
        Publisher authentication = tokenValidator.validateToken(accessToken)

        then:
        Flowable.fromPublisher(authentication).blockingFirst()

        and:
        Flowable.fromPublisher(authentication).blockingFirst().getAttributes().get(JwtClaims.EXPIRATION_TIME)
    }

    void 'refresh token does not contain expiration date'() {
        when:
        HttpRequest request = HttpRequest.create(HttpMethod.POST, '/login')
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .body(new UsernamePasswordCredentials('euler', 'password')) // <4>
        HttpResponse<AccessRefreshToken> rsp = client.toBlocking().exchange(request, AccessRefreshToken)

        then:
        rsp.status.code == 200
        rsp.body.isPresent()

        when:
        String refreshToken = rsp.body.get().refreshToken

        then:
        refreshToken

        when:
        Publisher authentication = tokenValidator.validateToken(refreshToken)

        then:
        Flowable.fromPublisher(authentication).blockingFirst()

        and:
        !Flowable.fromPublisher(authentication).blockingFirst().getAttributes().get(JwtClaims.EXPIRATION_TIME)
    }

    TokenValidator getTokenValidator() {
        embeddedServer.applicationContext.getBean(JwtTokenValidator.class) // <6>
    }
}
