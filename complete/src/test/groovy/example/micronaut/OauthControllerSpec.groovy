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
import io.micronaut.security.token.jwt.endpoints.TokenRefreshRequest
import io.micronaut.security.token.jwt.generator.claims.JwtClaims
import io.micronaut.security.token.jwt.render.AccessRefreshToken
import io.micronaut.security.token.jwt.render.BearerAccessRefreshToken
import io.micronaut.security.token.jwt.validator.JwtTokenValidator
import io.micronaut.security.token.validator.TokenValidator
import io.reactivex.Flowable
import org.reactivestreams.Publisher
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class OauthControllerSpec extends Specification {

    @Shared
    @AutoCleanup  // <1>
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer) // <2>

    @Shared
    @AutoCleanup  // <1>
    HttpClient client = HttpClient.create(embeddedServer.URL) // <3>

    void '/oauth/access_token endpoint returns BAD request if required parameters not present'() {
        when:
        HttpRequest request = HttpRequest.create(HttpMethod.POST, '/oauth/access_token')
                .accept(MediaType.APPLICATION_FORM_URLENCODED_TYPE) // <4>
        client.toBlocking().exchange(request)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status.code == 400
    }

    void 'Users can generate a new token by requesting to /oauth/access_token with refresh token'() {
        when:
        HttpRequest request = HttpRequest.create(HttpMethod.POST, '/login')
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .body(new UsernamePasswordCredentials('euler', 'password'))  // <4>
        HttpResponse<BearerAccessRefreshToken> rsp = client.toBlocking().exchange(request, BearerAccessRefreshToken)

        then:
        rsp.status.code == 200
        rsp.body.isPresent()

        when:
        String accessToken = rsp.body.get().accessToken
        String refreshToken = rsp.body.get().refreshToken

        then:
        accessToken
        refreshToken

        when:
        sleep(1_000)
        request = HttpRequest.create(HttpMethod.POST, '/oauth/access_token')
                .contentType(MediaType.APPLICATION_JSON)
                .body(new TokenRefreshRequest("refresh_token", refreshToken)) // <4>
        HttpResponse<AccessRefreshToken> tokenRsp = client.toBlocking().exchange(request, AccessRefreshToken)

        then:
        tokenRsp.status.code == 200
        tokenRsp.body.isPresent()

        and: 'a new access token was generated'
        tokenRsp.body.get().accessToken
        tokenRsp.body.get().accessToken != accessToken

        when:
        TokenValidator tokenValidator = embeddedServer.applicationContext.getBean(JwtTokenValidator) // <5>
        Publisher authentication = tokenValidator.validateToken(accessToken)

        then:
        Flowable.fromPublisher(authentication).blockingFirst()

        and:
        Flowable.fromPublisher(authentication).blockingFirst().getAttributes().get(JwtClaims.EXPIRATION_TIME)
    }
}