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

static const char *const usages[] = {
    "l4_lb [options] [[--] args]",
    "l4_lb [options]",
    NULL,
};

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

static int ifindex_iface = 0;
static __u32 xdp_flags = 0;

static void cleanup_ifaces() {
    __u32 curr_prog_id = 0;

    if (ifindex_iface != 0) {
        if (!bpf_xdp_query_id(ifindex_iface, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface);
            }
        }
    }
}

void sigint_handler(int sig_no) {
    log_debug("Closing program...");
    cleanup_ifaces();
    exit(0);
}

int main(int argc, const char **argv) {

    // ARGPARSE

    const char *config_file = NULL;
    const char *iface = NULL;
    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('i', "iface", &iface, "Interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('c', "config", &config_file, "path to the config file", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(
        &argparse,
        "\n[Exercise 1] This software attaches an XDP program to the interface specified in the "
        "input parameter",
        "\nIf '-p' argument is specified, the interface will be put in promiscuous mode");
    argc = argparse_parse(&argparse, argc, argv);

    if (iface != NULL) {
        log_info("XDP program will be attached to %s interface", iface);
        ifindex_iface = if_nametoindex(iface);
        if (!ifindex_iface) {
            log_fatal("Error while retrieving the ifindex of %s", iface);
            exit(1);
        } else {
            log_info("Got ifindex for iface: %s, which is %d", iface, ifindex_iface);
        }
    } else {
        log_error("Error, you must specify the interface where to attach the XDP program");
        exit(1);
    }

    // YAML PARSE
    struct config *conf;

    cyaml_err_t err;
    err = cyaml_load_file(config_file, &config, &config_schema, (void **)&conf, NULL);

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

    struct in_addr vip;
    int ret = inet_pton(AF_INET, conf->vip, &vip);
    if (ret != 1) {
        log_error("Failed to convert VIP %s to integer", conf->vip);
        return 1;
    }

    log_info("Setting rodata");
    skel->rodata->l4_lb_cfg.vip = vip;
    skel->rodata->l4_lb_cfg.backend_count = conf->backends_count;

    bpf_program__set_type(skel->progs.l4_lb, BPF_PROG_TYPE_XDP);
    /* Load and verify BPF programs */
    if (l4_lb_bpf__load(skel)) {
        log_fatal("Error while loading BPF skeleton");
        exit(1);
    }

    int backend_map = bpf_map__fd(skel->maps.backend_map);
    if (backend_map < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        return 1;
    }

    // Access data
    printf("VIP: %s\n", conf->vip);
    printf("Backends %ld:\n", conf->backends_count);

    for (int i = 0; i < conf->backends_count; i++) {
        log_info("Loading IP %s", conf->backends[i].ip);

        // Convert the IP to an integer
        struct in_addr addr;
        int ret = inet_pton(AF_INET, conf->backends[i].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", conf->backends[i].ip);
            continue;
        }

        bpf_map_update_elem(backend_map, &i, &addr, 0);
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    if (sigaction(SIGTERM, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface, bpf_program__fd(skel->progs.l4_lb), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching the XDP program to the interface");
        goto cleanup;
    }

    log_info("Successfully attached!");

cleanup:
    cleanup_ifaces();
    l4_lb_bpf__destroy(skel);
    log_info("Program stopped correctly");
    cyaml_free(&config, &config_schema, conf, 0);
    return 0;
}
