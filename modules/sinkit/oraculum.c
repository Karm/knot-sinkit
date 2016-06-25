/*  Author: Michal Karm Babacek

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <curl/curl.h>
#include <sys/timeb.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include "modules/sinkit/oraculum.h"
#include "modules/sinkit/uthash.h"
#include "lib/layer.h"

#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "oraculum", fmt)
#define ERR_MSG(fmt...) fprintf(stderr, fmt)

#define API_REQUEST_CONTENT_TYPE "Content-Type: application/json"
#define USER_AGENT "Knot-resolver Sinkit/0.1"
// What could possibly go wrong?
#define SINKIT_ORACULUM_URL_MAX_LEN 1024

#define TESTING

struct CacheEntry {
    time_t timestamp;
    char *key;
    char *value;
    UT_hash_handle hh;
};
struct CacheEntry *cache = NULL;

struct oraculum_response {
    size_t size;
    char* response_body;
};

CURL *curl;
CURLcode res;
struct oraculum_response data;
FILE *headerfile;
static const char *pCertFile = "testcert.pem";
static const char *pCACertFile ="cacert.pem";
const char *pKeyName = "testkey.pem";
const char *pKeyType = "PEM";
struct curl_slist *headers = NULL;

time_t recovery_sleep_timestamp = 0;


// Control settings, call init_connection() first.

static char *sinkit_oraculum_url;
static char *sinkit_access_token;
static int sinkit_max_cache_size;
static int sinkit_cache_ttl_s;
static long sinkit_curlopt_tcp_keepidle_s;
static long sinkit_curlopt_tcp_keepintvl_s;
static int sinkit_oraculum_hard_timeout_ms;
static int sinkit_oraculum_recovery_sleep_s;
static char *sinkit_oraculum_negative_response_string;
static int sinkit_oraculum_negative_response_string_len;
static char *sinkit_oraculum_nocache_response_string;
static int sinkit_oraculum_nocache_response_string_len;
static int sinkit_max_api_response_body_size;
static bool sinkit_sinkhole_based_on_ip_address;


/*static long get_nanos() {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (long)ts.tv_sec * 1000000000L + ts.tv_nsec;
}*/

char* find_in_cache(const char *key) {
    struct CacheEntry *entry;
    HASH_FIND_STR(cache, key, entry);
    if (entry) {
        time_t age = time (NULL) - entry->timestamp;
        if(age < sinkit_cache_ttl_s) {
            DEBUG_MSG(NULL, "Record's age is %ld, which is fine.\n", age);
            // remove it (so the subsequent add will throw it on the front of the list)
            HASH_DELETE(hh, cache, entry);
            HASH_ADD_KEYPTR(hh, cache, entry->key, strlen(entry->key), entry);
            return entry->value;
        } else {
            DEBUG_MSG(NULL, "Record is older then %d s, it's: %ld s old. Let's get rid of it.\n", sinkit_cache_ttl_s, age);
            HASH_DELETE(hh, cache, entry);
            free(entry->key);
            free(entry->value);
            free(entry);
            return NULL;
        }
    }
    return NULL;
}

void add_to_cache(const char *key, const char *value) {
    struct CacheEntry *entry, *tmp_entry;
    entry = malloc(sizeof(struct CacheEntry));
    entry->key = strdup(key);
    entry->value = strdup(value);
    time(&entry->timestamp);
    HASH_ADD_KEYPTR(hh, cache, entry->key, strlen(entry->key), entry);
    DEBUG_MSG(NULL, "Adding to cache key: %s, value: %s, timestamp: %ld\n", entry->key, entry->value, entry->timestamp);
    // prune the cache to sinkit_max_cache_size
    if (HASH_COUNT(cache) >= sinkit_max_cache_size) {
        HASH_ITER(hh, cache, entry, tmp_entry) {
            // prune the first entry (loop is based on insertion order so this deletes the oldest item)
            HASH_DELETE(hh, cache, entry);
            free(entry->key);
            free(entry->value);
            free(entry);
            break;
        }
    }
}

// TODO: Get rid of malloc, make use of static memory
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *buff) {
    struct oraculum_response *data = buff;
    size_t index = data->size;
    size_t n = (size * nmemb);
    char* tmp;

    data->size += (size * nmemb);

    DEBUG_MSG(NULL, "data at %p size=%ld nmemb=%ld\n", ptr, size, nmemb);

    tmp = realloc(data->response_body, data->size + 1); // +1 for '\0'

    if(tmp) {
        data->response_body = tmp;
    } else {
        //TODO: At this point, we should probably outright crash.
        die("Failed to allocate memory.\n");
    }

    memcpy((data->response_body + index), ptr, n);
    data->response_body[data->size] = '\0';

    return size * nmemb;
}

void init_connection() {
    DEBUG_MSG(NULL, "init_connection entry: done\n");

    // Control constants
    char *tmp_value;
    sinkit_oraculum_url = getenv("SINKIT_ORACULUM_URL");
    if(!sinkit_oraculum_url) {
        die("SINKIT_ORACULUM_URL environment variable must be set to something like http://feedcore-lb.core:8080/sinkit/rest/blacklist/dns\n");
    }

    sinkit_access_token = getenv("SINKIT_ACCESS_TOKEN");
    if(!sinkit_access_token || strstr(sinkit_access_token, "X-sinkit-token: ") == NULL) {
        die("SINKIT_ACCESS_TOKEN environment variable must be set to something like: \"X-sinkit-token: xo3ku54321wstrf43265d19a88ff61hfer342645\", including the X-sinkit-token part.\n");
    }

    tmp_value = getenv("SINKIT_MAX_CACHE_SIZE");
    if(!tmp_value) {
        die("SINKIT_MAX_CACHE_SIZE environment variable must be set to something > 0, e.g. 100000.\n");
    }
    sinkit_max_cache_size = atoi(tmp_value);
    if(!sinkit_max_cache_size || sinkit_max_cache_size <= 0) {
        die("SINKIT_MAX_CACHE_SIZE environment variable must be set to something > 0, e.g. 100000.\n");
    }

    tmp_value = getenv("SINKIT_CACHE_TTL_S");
    if(!tmp_value) {
        die("SINKIT_CACHE_TTL_S environment variable must be set to something > 0, e.g. 300.\n");
    }
    sinkit_cache_ttl_s = atoi(tmp_value);
    if(!sinkit_cache_ttl_s || sinkit_cache_ttl_s <= 0) {
        die("SINKIT_CACHE_TTL_S environment variable must be set to something > 0, e.g. 300.\n");
    }

    tmp_value = getenv("SINKIT_ORACULUM_HARD_TIMEOUT_MS");
    if(!tmp_value) {
        die("SINKIT_ORACULUM_HARD_TIMEOUT_MS environment variable must be set to something > 0, e.g. 1200.\n");
    }
    sinkit_oraculum_hard_timeout_ms = atoi(tmp_value);
    if(!sinkit_oraculum_hard_timeout_ms || sinkit_oraculum_hard_timeout_ms <= 0) {
        die("SINKIT_ORACULUM_HARD_TIMEOUT_MS environment variable must be set to something > 0, e.g. 1200.\n");
    }

    tmp_value = getenv("SINKIT_ORACULUM_RECOVERY_SLEEP_S");
    if(!tmp_value) {
        die("SINKIT_ORACULUM_RECOVERY_SLEEP_S environment variable must be set to something > 0, e.g. 20.\n");
    }
    sinkit_oraculum_recovery_sleep_s = atoi(tmp_value);
    if(!sinkit_oraculum_recovery_sleep_s || sinkit_oraculum_recovery_sleep_s <= 0) {
        die("SINKIT_ORACULUM_RECOVERY_SLEEP_S environment variable must be set to something > 0, e.g. 20.\n");
    }

    sinkit_oraculum_negative_response_string = getenv("SINKIT_ORACULUM_NEGATIVE_RESPONSE_STRING");
    if(!sinkit_oraculum_negative_response_string) {
        die("SINKIT_ORACULUM_NEGATIVE_RESPONSE_STRING environment variable must be set to something like \"null\" (really, null) or any other string API sends back.\n");
    }
    sinkit_oraculum_negative_response_string_len = strlen(sinkit_oraculum_negative_response_string);

    sinkit_oraculum_nocache_response_string = getenv("SINKIT_ORACULUM_NOCACHE_RESPONSE_STRING");
    if(!sinkit_oraculum_nocache_response_string) {
        die("SINKIT_ORACULUM_NOCACHE_RESPONSE_STRING environment variable must be set to something like \"nocache\" or any other string API sends back.\n");
    }
    sinkit_oraculum_nocache_response_string_len = strlen(sinkit_oraculum_nocache_response_string);

    tmp_value = getenv("SINKIT_MAX_API_RESPONSE_BODY_SIZE");
    if(!tmp_value) {
        die("SINKIT_MAX_API_RESPONSE_BODY_SIZE environment variable must be set to something > 0, e.g. 32 or whatever is the maximal expected string length returned by API.\n");
    }
    sinkit_max_api_response_body_size = atoi(tmp_value);
    if(!sinkit_max_api_response_body_size || sinkit_max_api_response_body_size <= 0) {
        die("SINKIT_MAX_API_RESPONSE_BODY_SIZE environment variable must be set to something > 0, e.g. 32 or whatever is the maximal expected string length returned by API.\n");
    }

    tmp_value = getenv("SINKIT_CURLOPT_TCP_KEEPIDLE_S");
    if(!tmp_value) {
        die("SINKIT_CURLOPT_TCP_KEEPIDLE_S environment variable must be set to something >= 0, e.g. 120.\n");
    }
    sinkit_curlopt_tcp_keepidle_s = atol(tmp_value);
    if(!sinkit_curlopt_tcp_keepidle_s || sinkit_curlopt_tcp_keepidle_s < 0) {
        die("SINKIT_CURLOPT_TCP_KEEPIDLE_S environment variable must be set to something >= 0, e.g. 120.\n");
    }

    tmp_value = getenv("SINKIT_CURLOPT_TCP_KEEPINTVL_S");
    if(!tmp_value) {
        die("SINKIT_CURLOPT_TCP_KEEPINTVL_S environment variable must be set to something > 0, e.g. 20.\n");
    }
    sinkit_curlopt_tcp_keepintvl_s = atol(tmp_value);
    if(!sinkit_curlopt_tcp_keepintvl_s || sinkit_curlopt_tcp_keepintvl_s <= 0) {
        die("SINKIT_CURLOPT_TCP_KEEPINTVL_S environment variable must be set to something > 0, e.g. 20.\n");
    }

    tmp_value = getenv("SINKIT_SINKHOLE_BASED_ON_IP_ADDRESS");
    if(!tmp_value) {
        die("SINKIT_SINKHOLE_BASED_ON_IP_ADDRESS environment variable must be set to either 1 or 0.\n");
    }
    sinkit_sinkhole_based_on_ip_address = atoi(tmp_value);
    if(sinkit_sinkhole_based_on_ip_address != 0 && sinkit_sinkhole_based_on_ip_address != 1) {
        die("SINKIT_SINKHOLE_BASED_ON_IP_ADDRESS environment variable must be set to either 1 or 0.\n");
    }


    data.size = 0;
    data.response_body = malloc(sinkit_max_api_response_body_size); // initial buffer TODO: get rid of malloc, we know its size
    if(NULL == data.response_body) {
        //TODO: At this point, we should probably outright crash.
        die("Failed to allocate memory.\n");
    }

    data.response_body[0] = '\0';
    DEBUG_MSG(NULL, "init_connection data: done\n");

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
     if(curl) {
       curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
       curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);

       //curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,"PEM");
       //curl_easy_setopt(curl, CURLOPT_SSLCERT, pCertFile);
       //curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, pKeyType);
       //curl_easy_setopt(curl, CURLOPT_SSLKEY, pKeyName);
       //curl_easy_setopt(curl, CURLOPT_CAINFO, pCACertFile);
       //curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
       curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, sinkit_oraculum_hard_timeout_ms);
       curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
       /* keep-alive idle time to 120 seconds */
       curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, sinkit_curlopt_tcp_keepidle_s);
       /* interval time between keep-alive probes: 20 seconds */
       curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, sinkit_curlopt_tcp_keepintvl_s);
#ifdef TESTING
       curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
       curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
       headers = curl_slist_append(headers, API_REQUEST_CONTENT_TYPE);
       headers = curl_slist_append(headers, sinkit_access_token);
       curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
       DEBUG_MSG(NULL, "init_connection curl: done\n");
     } else {
        die("CURL wasn't initialized.");
    }
}

void free_connection() {
    curl_slist_free_all(headers);
    if(curl) {
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    free(data.response_body);
}

bool api_call(const char* url) {
    if(recovery_sleep_timestamp != 0) {
        time_t recovery_sleep_elapsed = time (NULL) - recovery_sleep_timestamp;
        if(recovery_sleep_elapsed < sinkit_oraculum_recovery_sleep_s) {
            DEBUG_MSG(NULL, "%d seconds elapsed from %d SINKIT_ORACULUM_RECOVERY_SLEEP_S, let's wait...\n", recovery_sleep_elapsed, sinkit_oraculum_recovery_sleep_s);
            return false;
        } else {
            DEBUG_MSG(NULL, "%d seconds elapsed from %d SINKIT_ORACULUM_RECOVERY_SLEEP_S, Oraculum is ENABLED now.\n", recovery_sleep_elapsed, sinkit_oraculum_recovery_sleep_s);
            recovery_sleep_timestamp = 0;
        }
    }
    data.size = 0;
    data.response_body[0] = '\0';
    if (curl) {
        char* value = find_in_cache(url);
        int nocache_response_cmp;
        if(value) {
            strncpy(data.response_body, value, sinkit_max_api_response_body_size);
            nocache_response_cmp = INT8_MAX;
        } else {
            curl_easy_setopt(curl, CURLOPT_URL, url);
            res = curl_easy_perform(curl);
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            if(res != CURLE_OK || http_code >= 400) {
                    ERR_MSG("API call failed, HTTP code: %ld, Msg: %s, URL: %s\n", http_code, curl_easy_strerror(res), url);
                    ERR_MSG("Calls to Oraculum are DISABLED for %d seconds.\n", sinkit_oraculum_recovery_sleep_s);
                    time(&recovery_sleep_timestamp);
                    return false;
            }
            nocache_response_cmp = strncmp(data.response_body, sinkit_oraculum_nocache_response_string, sinkit_oraculum_nocache_response_string_len);
            if(nocache_response_cmp != 0) {
                add_to_cache(url, data.response_body);
            } else {
                DEBUG_MSG(NULL, "data.response_body: %s\n url: %s\n is not cacheable. add_to_cache skipped. nocache_response_cmp: %d\n", data.response_body, url, nocache_response_cmp);
            }
        }
        DEBUG_MSG(NULL, "data.response_body: %s\n url: %s\n from cache: %s\n", data.response_body, url, (value) ? "true" : "false");
        int negative_response_cmp = strncmp(data.response_body, sinkit_oraculum_negative_response_string, sinkit_oraculum_negative_response_string_len);
        DEBUG_MSG(NULL, "negative_response_cmp: %d\n", negative_response_cmp);
        DEBUG_MSG(NULL, "nocache_response_cmp: %d\n", nocache_response_cmp);

        /*
         * sinkit_oraculum_nocache_response_string present:  we DO NOT sinkhole and we DO NOT cache
         * sinkit_oraculum_negative_response_string present: we DO NOT sinkhole and we DO cache
         * anything else:                                    we DO sinkhole and we DO cache
         */

        return negative_response_cmp != 0 && nocache_response_cmp != 0;

    } else {
        die("CURL wasn't initialized.");
    }
}

char url_string[SINKIT_ORACULUM_URL_MAX_LEN + 1 + INET6_ADDRSTRLEN + 1 + KNOT_DNAME_MAXLEN + 1 + KNOT_DNAME_MAXLEN + 1];
bool address_malevolent(const char *client_address, const char *address, const char *hostname) {
    DEBUG_MSG(NULL, "Address %s\n", address);
    //127.0.0.1/109.123.209.192/hofyland.cz
    memset(&url_string, 0, sizeof(url_string));

    strcat(url_string, sinkit_oraculum_url);
    strcat(url_string, "/");
    strcat(url_string, client_address);
    strcat(url_string, "/");
    strcat(url_string, address);
    strcat(url_string, "/");
    strcat(url_string, hostname);

    bool result = api_call(url_string);

    // If the feature is off, we still carry out the API call, but we always return false - not malevolent.
    if(sinkit_sinkhole_based_on_ip_address) {
        DEBUG_MSG(NULL, "VERDICT: %d\n", result);
        return result;
    } else {
        DEBUG_MSG(NULL, "VERDICT: %d\n", false);
        return false;
    }
}

bool hostname_malevolent(const char *client_address, const char *hostname) {
    DEBUG_MSG(NULL, "Hostname %s\n", hostname);
    //127.0.0.1/hofyland.cz/hofyland.cz
    memset(&url_string, 0, sizeof(url_string));

    strcat(url_string, sinkit_oraculum_url);
    strcat(url_string, "/");
    strcat(url_string, client_address);
    strcat(url_string, "/");
    strcat(url_string, hostname); // yes, duplicate
    strcat(url_string, "/");
    strcat(url_string, hostname);

    bool result = api_call(url_string);
    DEBUG_MSG(NULL, "VERDICT: %d\n", result);
    return result;
}
