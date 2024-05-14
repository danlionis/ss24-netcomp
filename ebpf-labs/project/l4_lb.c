// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <argparse.h>
#include <net/if.h>

#include <cyaml/cyaml.h>

#include "l4_lb.skel.h"

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#include "log.h"

// Define the structure to hold the YAML data
struct backend {
    char *ip;
};

struct config {
    char *vip;
    struct backend *backends;
    size_t backends_count;
};

static const cyaml_schema_field_t backend_field_schema[] = {
    CYAML_FIELD_STRING_PTR("ip", CYAML_FLAG_POINTER, struct backend, ip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END,
};

static const cyaml_schema_value_t backend_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct backend, backend_field_schema),
};

/* CYAML mapping schema fields array for the top level mapping. */
static const cyaml_schema_field_t top_mapping_schema[] = {
    CYAML_FIELD_STRING_PTR("vip", CYAML_FLAG_POINTER, struct config, vip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_SEQUENCE("backends", CYAML_FLAG_POINTER, struct config, backends, &backend_schema,
                         0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

/* CYAML value schema for the top level mapping. */
static const cyaml_schema_value_t config_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct config, top_mapping_schema),
};

static const cyaml_config_t config = {
    .log_fn = cyaml_log,            /* Use the default logging function. */
    .mem_fn = cyaml_mem,            /* Use the default memory allocator. */
    .log_level = CYAML_LOG_WARNING, /* Logging errors and warnings only. */
};

int main(int argc, const char **argv) {
    struct config *conf;

    // Load YAML
    cyaml_err_t err;
    // err = cyaml_load_data((const uint8_t *)yaml, strlen(yaml), &config, &config_schema,
    //                       (void *)&conf, NULL);
    printf("%s\n", argv[1]);
    err = cyaml_load_file(argv[1], &config, &config_schema, (void **)&conf, NULL);

    if (err != CYAML_OK) {
        printf("Error loading YAML: %s\n", cyaml_strerror(err));
        return 1;
    }

    // Load BPF program
    struct l4_lb_bpf *skel = NULL;

    log_info("Opening BPF skel");
    skel = l4_lb_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }

    bpf_program__set_type(skel->progs.l4_lb, BPF_PROG_TYPE_XDP);
    int backend_map = bpf_map__fd(skel->maps.backend_map);
    if (backend_map < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        return 1;
    }

    // Access data
    printf("VIP: %s\n", conf->vip);
    printf("Backends %ld:\n", conf->backends_count);
    size_t next_idx = 0;
    for (size_t i = 0; i < conf->backends_count; i++) {
        log_info("Loading IP %s", conf->backends[i].ip);

        // Convert the IP to an integer
        struct in_addr addr;
        int ret = inet_pton(AF_INET, conf->backends[i].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", conf->backends[i].ip);
            continue;
        }

        bpf_map_update_elem(backend_map, &next_idx, &addr, 0);
        next_idx += 1;
    }

    // Free memory
    cyaml_free(&config, &config_schema, conf, 0);
    return 0;
}
