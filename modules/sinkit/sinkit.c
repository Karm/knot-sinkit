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

#include <libknot/packet/pkt.h>
#include <libknot/descriptor.h>
#include <libknot/rrtype/aaaa.h>

#include <ucw/mempool.h>
#include <contrib/cleanup.h>
#include <sys/socket.h>

#include "daemon/engine.h"
#include "lib/zonecut.h"
#include "lib/module.h"
#include "lib/layer.h"
#include "lib/resolve.h"

#include <libknot/rrtype/rdname.h>
#include "lib/rplan.h"
#include "lib/layer/iterate.h"
#include "lib/dnssec/ta.h"
#include <arpa/inet.h>

#include "modules/sinkit/oraculum.h"

/* Defaults */
#define DEFAULT_SERVER "localhost"

static const char *sinkit_sinkhole;
static bool sinkit_oraculum_disabled;

struct hostname_bundle {
    char *hostname_str;
    knot_dname_t *hostname_dname;
};

static int load(struct kr_module *module, const char *path) {
    DEBUG_MSG("Sinkit module loaded.\n");
    //DEBUG_MSG("Oraculum lives at %s\n", path);

    sinkit_sinkhole = getenv("SINKIT_SINKHOLE");
    if(!sinkit_sinkhole) {
        die("SINKIT_SINKHOLE environment variable must be set to an IP address.\n");
    }

    char *tmp_value = getenv("SINKIT_ORACULUM_DISABLED");
    if(!tmp_value) {
        die("SINKIT_ORACULUM_DISABLED environment variable must be set to either 1 or 0.\n");
    }
    sinkit_oraculum_disabled = atoi(tmp_value);
    if(sinkit_oraculum_disabled != 0 && sinkit_oraculum_disabled != 1) {
        die("SINKIT_ORACULUM_DISABLED environment variable must be set to either 1 or 0.\n");
    }

    init_connection();
    return kr_ok();
}

static void unload(struct kr_module *module) {
    free_connection();
    struct kr_zonecut *sinkit = module->data;
    if (sinkit) {
        kr_zonecut_deinit(sinkit);
        module->data = NULL;
    }
}

static int parse_addr_str(struct sockaddr_storage *sa, const char *addr) {
    int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
    memset(sa, 0, sizeof(struct sockaddr_storage));
    sa->ss_family = family;
    char *addr_bytes = (char *)kr_inaddr((struct sockaddr *)sa);
    if (inet_pton(family, addr, addr_bytes) < 1) {
        return kr_error(EILSEQ);
    }
    return 0;
}

static bool is_malevolent_address(const uint8_t *addr, size_t len, const char *hostname, const char *client_address) {
    if (len == sizeof(struct in_addr)) {
        /* Filter ANY and 127.0.0.0/8 */
        // OMG, ntohl changes byte order
        uint32_t ip_host = ntohl(*(const uint32_t *)(addr));
        if (ip_host == 0 || (ip_host & 0xff000000) == 0x7f000000) {
           // TODO: We don't know what we will be returning...return false; ?
        }
        char buffer[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(*(const uint32_t *)(addr)),buffer,sizeof(buffer));
        DEBUG_MSG("Resolved IPv4: %s\n", buffer);
        return address_malevolent(client_address, buffer, hostname);

    } else if (len == sizeof(struct in6_addr)) {
        struct in6_addr ip6_mask;
        memset(&ip6_mask, 0, sizeof(ip6_mask));
        /* All except last byte are zeroed, last byte defines ANY/::1 */
        if (memcmp(addr, ip6_mask.s6_addr, sizeof(ip6_mask.s6_addr) - 1) == 0) {
            // >1 i.e. 0 any, 1 localhost
            // We don't know what we will be returning...   return (addr[len - 1] > 1);
        }
        char buffer[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(*(const uint32_t *)(addr)),buffer,sizeof(buffer));
        DEBUG_MSG("Resolved IPv6: %s\n", buffer);
        return address_malevolent(client_address, buffer, hostname);
    } else {
          DEBUG_MSG("SHIT\n");
    }

    return false;
}

/* Thread unsafe - allocate & free? Use module memory pool? */
static char name_str[KNOT_DNAME_MAXLEN];
static void sanitize_hostname(knot_dname_t *hostname) {
    memset(&name_str, 0, sizeof(name_str));
    //char name_str[KNOT_DNAME_MAXLEN];
    knot_dname_to_str(name_str, hostname, sizeof(name_str));
    DEBUG_MSG("rr->owner is %s\n", name_str);
    // Sanitize the trailing dot.
    size_t actual_length = strlen(name_str);
    if(name_str[actual_length-1] == '.') {
        name_str[actual_length-1] = '\0';
    }
}

static int collect(knot_layer_t *ctx) {
    struct kr_request *param = ctx->data;
    struct kr_rplan *rplan = &param->rplan;

    const struct sockaddr *sa = param->qsource.addr;
    struct sockaddr_in *sin = (struct sockaddr_in *) sa;
    //free?
    const char *client_address =  inet_ntoa(sin->sin_addr);
    DEBUG_MSG("Client IPv4 address: %s\n", client_address);

    if (!sinkit_oraculum_disabled && rplan->resolved.len > 0) {
        struct kr_query *last = array_tail(rplan->resolved);
        const knot_pktsection_t *ns = knot_pkt_section(param->answer, KNOT_ANSWER);

        bool sinkit = false;
        uint16_t rclass;

        DEBUG_MSG("ns->count %d\n", ns->count);

        for (unsigned i = 0; i < ns->count; ++i) {
            const knot_rrset_t *rr = knot_pkt_rr(ns, i);

            if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA) {
                sanitize_hostname(rr->owner);
                //TODO: NULL const char *client_address, and its size...
                if (hostname_malevolent(client_address, name_str)) {
                    sinkit = true;
                    rclass = rr->rclass;
                }

                for (unsigned j = 0; j < rr->rrs.rr_count; j++) {
                    const knot_rdata_t *rdata = rr->rrs.data;
                     if (is_malevolent_address(knot_rdata_data(rdata), knot_rdata_rdlen(rdata), name_str, client_address)) {
                         DEBUG_MSG("XXX LISTED ADDRESS\n");
                         sinkit = true;
                         rclass = rr->rclass;
                     }
                }
            }
        }

        if (sinkit) {
            uint16_t msgid = knot_wire_get_id(param->answer->wire);
            kr_pkt_recycle(param->answer);

            knot_pkt_put_question(param->answer, last->sname, last->sclass, last->stype);
            knot_pkt_begin(param->answer, KNOT_ANSWER); //AUTHORITY?

            struct sockaddr_storage sinkhole;
            if (parse_addr_str(&sinkhole, sinkit_sinkhole) != 0) {
                return kr_error(EINVAL);
            }

            size_t addr_len = kr_inaddr_len((struct sockaddr *)&sinkhole);
            const uint8_t *raw_addr = (const uint8_t *)kr_inaddr((struct sockaddr *)&sinkhole);
            static knot_rdata_t rdata_arr[RDATA_ARR_MAX];

            knot_wire_set_id(param->answer->wire, msgid);

            kr_pkt_put(param->answer, last->sname, 120, rclass, KNOT_RRTYPE_A, raw_addr, addr_len);

            return KNOT_STATE_DONE;
        }
    }
    return ctx->state;
}

/*
 * Module implementation.
 */
KR_EXPORT
const knot_layer_api_t *sinkit_layer(struct kr_module *module) {
    static knot_layer_api_t _layer = {
        .finish = &collect,
    };
    /* Store module reference */
    _layer.data = module;
    return &_layer;
}

KR_EXPORT
int sinkit_init(struct kr_module *module) {
    module->data = NULL;
    return 0;
}

KR_EXPORT
int sinkit_config(struct kr_module *module, const char *conf) {
    unload(module);
    if (!conf || strlen(conf) < 1) {
        conf = DEFAULT_SERVER;
    }
    return load(module, conf);
}

KR_EXPORT
int sinkit_deinit(struct kr_module *module) {
    unload(module);
    return kr_ok();
}

KR_MODULE_EXPORT(sinkit);
