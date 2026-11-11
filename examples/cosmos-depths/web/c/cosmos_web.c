/* cosmos.h for the browser: thin C side of library_cosmos.js. The calls
 * that block (host, join, record put) must come from a worker thread: they
 * start the JS promise on the main thread and wait on a futex for it. */
#include <emscripten.h>
#include <emscripten/threading.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cosmos.h"

extern int cw_init(const char *ns, const char *key, int queue, char *err);
extern int cw_poll(int id, int32_t *ev, double *t, uint8_t *data, int cap, char *kind, char *key, uint8_t *pub, char *msg);
extern int cw_send(int id, uint32_t peer, int ch, const void *d, int len, int rel, char *err);
extern void cw_start(int op, int id, const char *a, const char *b, const void *d, int len, uint32_t ttl, void *wait);
extern int cw_query(int id, const char *kind, const char *key, uint32_t req, char *err);
extern int cw_subscribe(int id, const char *kind, const char *key, char *err);
extern int cw_unsubscribe(int id, int sub, char *err);
extern uint32_t cw_host_peer(int id);
extern double cw_dropped(int id);
extern int cw_peer_id(int id, uint32_t peer, uint8_t *out, int cap, char *err);
extern void cw_shutdown(int id);

#define DATA_CAP (66 * 1024)

struct cosmos_t {
    int id;
    int32_t ev[12];
    double t[2];
    uint8_t data[DATA_CAP];
    char kind[72];
    char key[264];
    uint8_t pub[64];
    char msg[256];
};

typedef struct { /* layout known to cw_start */
    _Atomic int32_t done;
    int32_t rc;
    char code[16];
    char err[256];
} Wait;

static _Thread_local char last_err[256];

static int32_t fail(int32_t rc, const char *msg) {
    snprintf(last_err, sizeof last_err, "%s", msg);
    return rc;
}

static int32_t check(int32_t rc, const char *err) {
    if (rc < 0) snprintf(last_err, sizeof last_err, "%s", err);
    return rc;
}

static int32_t run(int op, cosmos_t *c, const char *a, const char *b, const void *d, size_t len, uint32_t ttl, char *code, size_t cap) {
    Wait w;
    memset(&w, 0, sizeof w);
    if (emscripten_is_main_browser_thread()) return fail(COSMOS_E_STATE, "blocking call on the main thread: call it from a worker");
    cw_start(op, c->id, a, b, d, (int)len, ttl, &w);
    while (!atomic_load(&w.done)) emscripten_futex_wait((void *)&w.done, 0, 50);
    if (w.rc < 0) return fail(w.rc, w.err);
    if (code) {
        if (strlen(w.code) + 1 > cap) return fail(COSMOS_E_BUFFER, "code buffer too small");
        strcpy(code, w.code);
    }
    return COSMOS_OK;
}

const char *cosmos_version(void) { return "0.1.0-web"; }

const char *cosmos_last_error(void) { return last_err; }

const char *cosmos_error_name(int32_t code) {
    static const char *names[] = {"COSMOS_OK", "COSMOS_E_NULL", "COSMOS_E_INVALID", "COSMOS_E_PANIC", "COSMOS_E_STATE",
                                  "COSMOS_E_NOT_FOUND", "COSMOS_E_FULL", "COSMOS_E_TIMEOUT", "COSMOS_E_NET", "COSMOS_E_TOO_LARGE",
                                  "COSMOS_E_RATE_LIMITED", "COSMOS_E_BACKLOG", "COSMOS_E_ENDED", "COSMOS_E_BUFFER", "COSMOS_E_IO"};
    return code <= 0 && code >= -14 ? names[-code] : "COSMOS_E_UNKNOWN";
}

cosmos_t *cosmos_init(const cosmos_config_t *cfg) {
    char err[256] = "";
    cosmos_t *c;
    int id;
    if (!cfg || !cfg->game_id) { fail(COSMOS_E_NULL, "no config or game_id"); return NULL; }
    id = cw_init(cfg->game_id, cfg->key_path, (int)cfg->event_queue, err);
    if (id <= 0) { fail(id, err); return NULL; }
    c = calloc(1, sizeof *c);
    if (!c) { cw_shutdown(id); fail(COSMOS_E_PANIC, "out of memory"); return NULL; }
    c->id = id;
    return c;
}

int32_t cosmos_host(cosmos_t *c, char *code_out, size_t cap) {
    if (!c || !code_out) return fail(COSMOS_E_NULL, "null argument");
    return run(1, c, NULL, NULL, NULL, 0, 0, code_out, cap);
}

int32_t cosmos_join(cosmos_t *c, const char *code) {
    if (!c || !code) return fail(COSMOS_E_NULL, "null argument");
    return run(2, c, code, NULL, NULL, 0, 0, NULL, 0);
}

int32_t cosmos_send(cosmos_t *c, uint32_t peer, uint8_t channel, const void *data, size_t len, int32_t reliable) {
    char err[256] = "";
    if (!c || (!data && len)) return fail(COSMOS_E_NULL, "null argument");
    return check(cw_send(c->id, peer, channel, data, (int)len, reliable != 0, err), err);
}

int32_t cosmos_poll(cosmos_t *c, cosmos_event_t *ev) {
    if (!c || !ev) return fail(COSMOS_E_NULL, "null argument");
    memset(ev, 0, sizeof *ev);
    if (!cw_poll(c->id, c->ev, c->t, c->data, DATA_CAP, c->kind, c->key, c->pub, c->msg)) return 0;
    ev->kind = c->ev[0];
    ev->peer = (uint32_t)c->ev[1];
    ev->channel = (uint8_t)c->ev[2];
    ev->reliable = (uint8_t)c->ev[3];
    ev->path = c->ev[4];
    ev->req_id = (uint32_t)c->ev[5];
    ev->error = c->ev[6];
    ev->index = (uint32_t)c->ev[7];
    ev->count = (uint32_t)c->ev[8];
    ev->data = c->data;
    ev->len = (size_t)c->ev[9];
    ev->publisher = c->pub;
    ev->publisher_len = (size_t)c->ev[10];
    ev->message = c->ev[11] ? c->msg : NULL;
    ev->record_kind = c->kind;
    ev->record_key = c->key;
    ev->issued_ms = (uint64_t)c->t[0];
    ev->expires_s = (uint64_t)c->t[1];
    return 1;
}

uint32_t cosmos_host_peer(const cosmos_t *c) { return c ? cw_host_peer(c->id) : 0; }

uint64_t cosmos_dropped_events(const cosmos_t *c) { return c ? (uint64_t)cw_dropped(c->id) : 0; }

int32_t cosmos_peer_id(cosmos_t *c, uint32_t peer, uint8_t *out, size_t cap) {
    char err[256] = "";
    if (!c || !out) return fail(COSMOS_E_NULL, "null argument");
    return check(cw_peer_id(c->id, peer, out, (int)cap, err), err);
}

int32_t cosmos_listen_addrs(cosmos_t *c, char *out, size_t cap) {
    if (!c || !out) return fail(COSMOS_E_NULL, "null argument");
    if (cap) out[0] = 0; /* browsers listen nowhere: peers come through signalling */
    return 0;
}

int32_t cosmos_record_put(cosmos_t *c, const char *kind, const char *key, const void *data, size_t len, uint32_t ttl_s) {
    if (!c || !kind || !key || (!data && len)) return fail(COSMOS_E_NULL, "null argument");
    return run(3, c, kind, key, data, len, ttl_s, NULL, 0);
}

int32_t cosmos_record_query(cosmos_t *c, const char *kind, const char *key, uint32_t req_id) {
    char err[256] = "";
    if (!c || !kind || !key) return fail(COSMOS_E_NULL, "null argument");
    return check(cw_query(c->id, kind, key, req_id, err), err);
}

int32_t cosmos_record_subscribe(cosmos_t *c, const char *kind, const char *key) {
    char err[256] = "";
    if (!c || !kind || !key) return fail(COSMOS_E_NULL, "null argument");
    return check(cw_subscribe(c->id, kind, key, err), err);
}

int32_t cosmos_record_unsubscribe(cosmos_t *c, int32_t sub) {
    char err[256] = "";
    if (!c) return fail(COSMOS_E_NULL, "null argument");
    return check(cw_unsubscribe(c->id, sub, err), err);
}

void cosmos_shutdown(cosmos_t *c) {
    if (!c) return;
    cw_shutdown(c->id);
    free(c);
}
