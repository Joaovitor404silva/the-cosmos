/* Cosmos chat: 4 instances in one process on loopback.
 * Instance 0 hosts and prints a join code, 1..3 join with it, everyone
 * broadcasts one line, then 0 puts a record and 2 queries it.
 * Build (x64 Native Tools prompt):
 *   cl /I include examples\chat.c /link target\debug\cosmos.dll.lib
 */
#include <stdio.h>
#include <string.h>
#include "cosmos.h"

#ifdef _WIN32
#include <windows.h>
static void nap(int ms) { Sleep((DWORD)ms); }
#else
#include <unistd.h>
static void nap(int ms) { usleep((useconds_t)ms * 1000); }
#endif

#define N 4
#define NOTE "meet at the north gate"

static cosmos_t *c[N];
static int joined[N], msgs[N];
static int found_record;

static int fail(const char *what, int r) {
    printf("FAIL %s: %s (%s)\n", what, cosmos_error_name(r), cosmos_last_error());
    return 1;
}

/* Drain every instance's events once. */
static void pump(void) {
    for (int i = 0; i < N; i++) {
        cosmos_event_t ev;
        while (cosmos_poll(c[i], &ev) > 0) {
            switch (ev.kind) {
            case COSMOS_EV_PEER_JOINED:
                joined[i]++;
                break;
            case COSMOS_EV_MESSAGE:
                /* ev.data is valid until the next cosmos_poll on c[i]. */
                printf("peer %d: from #%u on ch %u: %.*s\n", i, ev.peer, ev.channel, (int)ev.len,
                       (const char *)ev.data);
                msgs[i]++;
                break;
            case COSMOS_EV_RECORD_RESULT:
                if (ev.req_id == 42 && ev.error == COSMOS_OK && ev.count > 0) {
                    printf("record: %s/%s = '%.*s'\n", ev.record_kind, ev.record_key, (int)ev.len,
                           (const char *)ev.data);
                    found_record = 1;
                }
                break;
            case COSMOS_EV_ERROR:
                printf("peer %d: error %s: %s\n", i, cosmos_error_name(ev.error), ev.message);
                break;
            default:
                break;
            }
        }
    }
}

/* Pump until `done()` or about `secs` seconds pass. */
static int wait_for(int (*done)(void), int secs) {
    for (int t = 0; t < secs * 100; t++) {
        pump();
        if (done()) return 1;
        nap(10);
    }
    return 0;
}

static int all_joined(void) {
    for (int i = 0; i < N; i++) if (joined[i] < N - 1) return 0;
    return 1;
}

static int all_messages(void) {
    for (int i = 0; i < N; i++) if (msgs[i] < N - 1) return 0;
    return 1;
}

static int got_record(void) { return found_record; }

int main(void) {
    char boot[1024], code[COSMOS_CODE_MAX];
    cosmos_config_t cfg;
    int r;

    printf("cosmos %s\n", cosmos_version());
    memset(&cfg, 0, sizeof cfg);
    cfg.game_id = "cosmos-chat";
    cfg.listen = "127.0.0.1";
    for (int i = 0; i < N; i++) {
        c[i] = cosmos_init(&cfg);
        if (!c[i]) return fail("init", -1);
        if (i == 0) {
            r = cosmos_listen_addrs(c[0], boot, sizeof boot);
            if (r < 0) return fail("listen_addrs", r);
            cfg.bootstrap = boot;
        }
    }

    /* Hosting publishes the code in the DHT; retry while the mesh forms. */
    for (int t = 0; (r = cosmos_host(c[0], code, sizeof code)) == COSMOS_E_NET && t < 60; t++) nap(500);
    if (r != COSMOS_OK) return fail("host", r);
    printf("code %s\n", code);

    for (int i = 1; i < N; i++) {
        r = cosmos_join(c[i], code);
        if (r != COSMOS_OK) return fail("join", r);
    }
    if (!wait_for(all_joined, 30)) return fail("all joined", COSMOS_E_TIMEOUT);
    for (int i = 0; i < N; i++) printf("peer %d: %d peers joined\n", i, joined[i]);

    for (int i = 0; i < N; i++) {
        char line[64];
        int n = snprintf(line, sizeof line, "hello from %d", i);
        r = cosmos_send(c[i], COSMOS_BROADCAST, 1, line, (size_t)n, 1);
        if (r != COSMOS_OK) return fail("send", r);
    }
    if (!wait_for(all_messages, 30)) return fail("messages", COSMOS_E_TIMEOUT);
    for (int i = 0; i < N; i++) printf("peer %d: got %d messages\n", i, msgs[i]);

    r = cosmos_record_put(c[0], "note", "lobby", NOTE, strlen(NOTE), 120);
    if (r != COSMOS_OK) return fail("record_put", r);
    for (int t = 0; t < 30 && !found_record; t++) {
        r = cosmos_record_query(c[2], "note", "lobby", 42);
        if (r != COSMOS_OK) return fail("record_query", r);
        wait_for(got_record, 2);
    }
    if (!found_record) return fail("record", COSMOS_E_TIMEOUT);

    unsigned long long dropped = 0;
    for (int i = N - 1; i >= 0; i--) {
        dropped += cosmos_dropped_events(c[i]);
        cosmos_shutdown(c[i]);
    }
    printf("dropped events: %llu\nCHAT OK\n", dropped);
    return 0;
}
