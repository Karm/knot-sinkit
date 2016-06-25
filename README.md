# knot-sinkit
Sinkit GO module for Knot DNS Resolver

## Expected env vars

    export SINKIT_SINKHOLE=127.0.0.1
    export SINKIT_ORACULUM_URL="http://localhost:8080/sinkit/rest/blacklist/dns"
    export SINKIT_ACCESS_TOKEN="X-sinkit-token: 765fred432129873462139874623897jasgfasjd"
    export SINKIT_MAX_CACHE_SIZE=10
    export SINKIT_CACHE_TTL_S=5
    export SINKIT_ORACULUM_HARD_TIMEOUT_MS=300
    export SINKIT_ORACULUM_RECOVERY_SLEEP_S=10
    export SINKIT_ORACULUM_DISABLED=0
    export SINKIT_ORACULUM_NEGATIVE_RESPONSE_STRING=null
    export SINKIT_ORACULUM_NOCACHE_RESPONSE_STRING=nocache
    export SINKIT_MAX_API_RESPONSE_BODY_SIZE=32
    export SINKIT_CURLOPT_TCP_KEEPIDLE_S=120
    export SINKIT_CURLOPT_TCP_KEEPINTVL_S=20
    export SINKIT_SINKHOLE_BASED_ON_IP_ADDRESS=0
