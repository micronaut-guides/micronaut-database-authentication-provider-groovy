package example.micronaut

import org.reactivestreams.Publisher

interface AuthoritiesFetcher {
    List<String> findAuthoritiesByUsername(String username)
}
