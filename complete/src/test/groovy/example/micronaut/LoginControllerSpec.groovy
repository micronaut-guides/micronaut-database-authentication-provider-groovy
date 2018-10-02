package example.micronaut

import io.micronaut.context.ApplicationContext
import io.micronaut.http.HttpMethod
import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.MediaType
import io.micronaut.http.client.HttpClient
import io.micronaut.http.client.exceptions.HttpClientResponseException
import io.micronaut.runtime.server.EmbeddedServer
import io.micronaut.security.authentication.Authentication
import io.micronaut.security.authentication.UserDetails
import io.micronaut.security.authentication.UsernamePasswordCredentials
import io.micronaut.security.token.jwt.render.AccessRefreshToken
import io.micronaut.security.token.jwt.validator.JwtTokenValidator
import io.micronaut.security.token.validator.TokenValidator
import io.reactivex.Flowable
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class LoginControllerSpec extends Specification {

    @Shared
    @AutoCleanup // <1>
    EmbeddedServer embeddedServer = ApplicationContext.run(EmbeddedServer)  // <2>

    @Shared
    @AutoCleanup // <1>
    HttpClient client = HttpClient.create(embeddedServer.URL) // <3>

    void 'attempt to access /login without supplying credentials server responds BAD REQUEST'() {
        when:
        HttpRequest request = HttpRequest.create(HttpMethod.POST, '/login')
                .accept(MediaType.APPLICATION_JSON_TYPE) // <4>
        client.toBlocking().exchange(request)

        then:
        HttpClientResponseException e = thrown(HttpClientResponseException)
        e.status.code == 400
    }

    void '/login with valid credentials for a database user returns 200 and access token and refresh token'() {
        when:
        HttpRequest request = HttpRequest.create(HttpMethod.POST, '/login')
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .body(new UsernamePasswordCredentials('sherlock', 'elementary')) // <4>
        HttpResponse<AccessRefreshToken> rsp = client.toBlocking().exchange(request, AccessRefreshToken)

        then:
        rsp.status.code == 200
        rsp.body.isPresent()
        rsp.body.get().accessToken
        rsp.body.get().refreshToken

        when:
        String accessToken = rsp.body.get().accessToken
        Authentication authentication = Flowable.fromPublisher(tokenValidator.validateToken(accessToken)).blockingFirst()
        println authentication.getAttributes()

        then:
        authentication.getAttributes()
        authentication.getAttributes().containsKey('roles')
        authentication.getAttributes().containsKey('iss')
        authentication.getAttributes().containsKey('exp')
        authentication.getAttributes().containsKey('iat')
    }

    TokenValidator getTokenValidator() {
        embeddedServer.applicationContext.getBean(JwtTokenValidator.class) // <5>
    }
}