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


#define DEBUG_MSG(qry, fmt...) QRDEBUG(qry, "oraculum",  fmt)

#define ORACULUM_URL "http://feedcore-lb.core:8080/sinkit/rest/blacklist/dns"
#define ORACULUM_HARD_TIMEOUT_MS 1200
#define ACCESS_TOKEN_HEADER_KEY "SINKIT_ACCESS_TOKEN"
#define ORACULUM_NEGATIVE_RESPONSE_STRING "null"
#define ORACULUM_NEGATIVE_RESPONSE_STRING_SIZE 4
#define API_REQUEST_CONTENT_TYPE "Content-Type: application/json"
#define USER_AGENT "Knot-resolver Sinkit/0.1"
#define MAX_API_RESPONSE_BODY_SIZE 32

#define TESTING
#define MAX_CACHE_SIZE 100000
#define CACHE_TTL_S 300

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
        if(age < CACHE_TTL_S) {
            DEBUG_MSG(NULL, "Record's age is %ld, which is fine.\n", age);
            // remove it (so the subsequent add will throw it on the front of the list)
            HASH_DELETE(hh, cache, entry);
            HASH_ADD_KEYPTR(hh, cache, entry->key, strlen(entry->key), entry);
            return entry->value;
        } else {
            DEBUG_MSG(NULL, "Record is older then %d s, it's: %ld s old. Let's get rid of it.\n", CACHE_TTL_S, age);
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
    // prune the cache to MAX_CACHE_SIZE
    if (HASH_COUNT(cache) >= MAX_CACHE_SIZE) {
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
    data.size = 0;
    data.response_body = malloc(MAX_API_RESPONSE_BODY_SIZE); // initial buffer TODO: get rid of malloc, we know its size
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
       curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, ORACULUM_HARD_TIMEOUT_MS);
       curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
       /* keep-alive idle time to 120 seconds */
       curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 120L);
       /* interval time between keep-alive probes: 20 seconds */
       curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 20L);
#ifdef TESTING
       curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif
       curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
       headers = curl_slist_append(headers, API_REQUEST_CONTENT_TYPE);
       const char* access_token = getenv(ACCESS_TOKEN_HEADER_KEY);
       if(!access_token) {
           die("Access token %s must be configured.", ACCESS_TOKEN_HEADER_KEY);
       }
       headers = curl_slist_append(headers, access_token);
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
    data.size = 0;
    data.response_body[0] = '\0';
    if (curl) {

        char* value = find_in_cache(url);
        if(value) {
            strncpy(data.response_body, value, MAX_API_RESPONSE_BODY_SIZE);
        } else {
            curl_easy_setopt(curl, CURLOPT_URL, url);
            res = curl_easy_perform(curl);
            if(res != CURLE_OK) {
                    DEBUG_MSG(NULL, "API call failed: %s, URL: %s\n", curl_easy_strerror(res), url);
                    return false;
            }
            add_to_cache(url, data.response_body);
        }
        DEBUG_MSG(NULL, "data.response_body: %s\n url: %s\n from cache: %s\n", data.response_body, url, (value) ? "true" : "false");
        int is_malevolent = strncmp(data.response_body, ORACULUM_NEGATIVE_RESPONSE_STRING, ORACULUM_NEGATIVE_RESPONSE_STRING_SIZE);
        DEBUG_MSG(NULL, "is_malevolent: %d\n", is_malevolent);
        return is_malevolent == 1;
    } else {
        die("CURL wasn't initialized.");
    }
}

char url_string[sizeof ORACULUM_URL + 1 + INET6_ADDRSTRLEN + 1 + KNOT_DNAME_MAXLEN + 1 + KNOT_DNAME_MAXLEN + 1];
bool address_malevolent(const char *client_address, const char *address, const char *hostname) {
    DEBUG_MSG(NULL, "Address %s\n", address);
    //127.0.0.1/109.123.209.192/hofyland.cz
    memset(&url_string, 0, sizeof(url_string));

    strcat(url_string, ORACULUM_URL);
    strcat(url_string, "/");
    strcat(url_string, client_address);
    strcat(url_string, "/");
    strcat(url_string, address);
    strcat(url_string, "/");
    strcat(url_string, hostname);

    return api_call(url_string);
}

bool hostname_malevolent(const char *client_address, const char *hostname) {
    DEBUG_MSG(NULL, "Hostname %s\n", hostname);
    //127.0.0.1/hofyland.cz/hofyland.cz
    memset(&url_string, 0, sizeof(url_string));

    strcat(url_string, ORACULUM_URL);
    strcat(url_string, "/");
    strcat(url_string, client_address);
    strcat(url_string, "/");
    strcat(url_string, hostname); // yes, duplicate
    strcat(url_string, "/");
    strcat(url_string, hostname);

    return api_call(url_string);
}
