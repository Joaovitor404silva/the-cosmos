/* Cosmos Depths: rules and networking, using only cosmos.h.
 *
 * Sync plane (channel 1), host authoritative:
 *   host -> all  LEVEL  seed + depth, reliable; everyone builds the map
 *   host -> all  SNAP   players + monsters + items, unreliable, 6 per second
 *   host -> all  EVENT  kill / death / pickup, reliable
 *   any -> any   HELLO  my tag (identity), reliable
 *   client->host INTENT step or bump-attack or descend, reliable, numbered
 *                and stamped with the level (an intent for an old level is
 *                dropped); the client moves at once (prediction) and replays
 *                its unacknowledged intents over every snapshot.
 * A late joiner gets LEVEL plus a reliable SNAP from the host. A snapshot
 * of a newer level also rebuilds it, so a lost LEVEL heals.
 * Only cosmos_host_peer() may send LEVEL / SNAP / EVENT; the host refuses
 * a HELLO tag already in use. Depth goes on the wire as u16.
 *
 * Async plane (records under key "d<depth>", so any run reaches them):
 *   "note"  [room, dx, dy, text]   a player's note on a floor tile
 *   "grave" [room, dx, dy, cause]  where and how a player died
 *   "lobby" [players, depth u16, code]  under key "open": a public run's
 *                                  listing, put every 20 s by its host
 *                                  while it opts in. Anyone can read the
 *                                  code and join (that is the point).
 *   "ghost" [room, dx, dy, tag]    where a living player is now; put every
 *                                  few seconds, short TTL. Other runs on
 *                                  the same depth draw it as a faint @; a
 *                                  tag of my own party is skipped.
 * Room index + offset inside the room places a mark on any map of that
 * depth. One record per player and kind per depth; a new one replaces it.
 *
 * cosmos_host / cosmos_join / cosmos_record_put block: they run on a
 * worker thread. cosmos_poll only runs on the thread calling game_update.
 * Wire integers are little-endian. */
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "depths.h"
#ifdef __EMSCRIPTEN__
#include <emscripten.h>
static void game_free_later(void *g) { game_free(g, 0); }
#endif

enum { JOB_HOST = 1, JOB_JOIN, JOB_PUT };
enum { CH_GAME = 1 };
enum { MSG_HELLO = 'H', MSG_LEVEL = 'L', MSG_INTENT = 'I', MSG_SNAP = 'S', MSG_EVENT = 'E' };
enum { EVT_KILL = 1, EVT_DEATH, EVT_PICKUP };

#define RECORD_TTL 1800u /* the SDK's cap: 30 minutes */
#define GHOST_TTL 15u
#define LOBBY_TTL 60u
#define VIEW 9           /* monsters notice players this close */
#define POTION_HP 8
#define CAUSE_MAX 40

/* ---- helpers ---- */

static void put_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put_u32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint16_t get_u16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t get_u32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static void copy_str(char *dst, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

/* Printable ASCII only: records and events come from other players. */
static void copy_text(char *dst, size_t cap, const uint8_t *src, size_t len) {
    size_t n = len < cap - 1 ? len : cap - 1;
    for (size_t i = 0; i < n; i++) dst[i] = (src[i] >= 32 && src[i] < 127) ? (char)src[i] : '?';
    dst[n] = 0;
}

static void log_add(Game *g, const char *fmt, ...) {
    va_list ap;
    memmove(g->log[0], g->log[1], sizeof g->log[0] * (LOG_LINES - 1));
    va_start(ap, fmt);
    vsnprintf(g->log[LOG_LINES - 1], sizeof g->log[0], fmt, ap);
    va_end(ap);
}

/* ---- config ---- */

void config_default(DepthsConfig *c) {
    memset(c, 0, sizeof *c);
    c->lan = 1;
    c->steam = -1;
    c->app_id = 480; /* a demo: Valve's Spacewar test app (a real game sets its own) */
}

int config_set(DepthsConfig *c, const char *name, const char *value) {
    if (!strcmp(name, "listen")) copy_str(c->listen, sizeof c->listen, value);
    else if (!strcmp(name, "bootstrap")) copy_str(c->bootstrap, sizeof c->bootstrap, value);
    else if (!strcmp(name, "key")) copy_str(c->key, sizeof c->key, value);
    else if (!strcmp(name, "cache")) copy_str(c->cache, sizeof c->cache, value);
    else if (!strcmp(name, "addr-file")) copy_str(c->addr_file, sizeof c->addr_file, value);
    else if (!strcmp(name, "lan")) c->lan = atoi(value);
    else if (!strcmp(name, "steam")) c->steam = atoi(value);
    else if (!strcmp(name, "app-id")) c->app_id = (uint32_t)strtoul(value, NULL, 10);
    else return 0;
    return 1;
}

/* key = value lines; '#' or ';' comments. */
void config_load_ini(DepthsConfig *c, const char *path) {
    char line[1200];
    FILE *f = fopen(path, "r");
    if (!f) return;
    while (fgets(line, sizeof line, f)) {
        char *eq = strchr(line, '='), *k = line, *v, *e;
        if (!eq || line[0] == '#' || line[0] == ';') continue;
        *eq = 0;
        v = eq + 1;
        while (isspace((unsigned char)*k)) k++;
        for (e = eq; e > k && isspace((unsigned char)e[-1]); e--) e[-1] = 0;
        while (isspace((unsigned char)*v)) v++;
        for (e = v + strlen(v); e > v && isspace((unsigned char)e[-1]); e--) e[-1] = 0;
        config_set(c, k, v);
    }
    fclose(f);
}

/* ---- worker jobs (blocking cosmos calls) ---- */

static int job_main(void *arg) {
    Job *j = arg;
    cosmos_t *c = j->g->c;
    int r;
    if (j->what == JOB_HOST) {
        /* COSMOS_E_NET right after start-up: no DHT peers yet, retry. */
        for (int t = 0; (r = cosmos_host(c, j->code, sizeof j->code)) == COSMOS_E_NET && t < 60 && !j->g->quitting; t++)
            plat_sleep(500);
    } else if (j->what == JOB_JOIN) {
        r = cosmos_join(c, j->code);
    } else {
        r = cosmos_record_put(c, j->kind, j->key, j->data, j->len, j->ttl);
    }
    j->result = r;
    if (r != COSMOS_OK) snprintf(j->err, sizeof j->err, "%s: %s", cosmos_error_name(r), cosmos_last_error());
    return 0;
}

static int job_start(Game *g, Job *j, int what) {
    if (j->thread) return 0;
    j->g = g;
    j->what = what;
    j->result = 0;
    j->err[0] = 0;
    j->thread = plat_thread(job_main, j);
    return j->thread != NULL;
}

static int job_finished(Job *j) {
    if (!j->thread || !plat_thread_done(j->thread)) return 0;
    plat_thread_join(j->thread);
    j->thread = NULL;
    return 1;
}

/* ---- world queries ---- */

int game_slot_of(const Game *g, uint32_t tag) {
    for (int i = 0; i < MAX_PLAYERS; i++) if (g->pl[i].active && g->pl[i].tag == tag) return i;
    return -1;
}

Player *game_me(Game *g) {
    int s = game_slot_of(g, g->my_tag);
    return s < 0 ? NULL : &g->pl[s];
}

int game_monster_at(const Game *g, int x, int y) {
    for (int i = 0; i < g->lv.n_mon; i++)
        if (g->lv.mon[i].alive && g->lv.mon[i].x == x && g->lv.mon[i].y == y) return i;
    return -1;
}

static int player_at(const Game *g, int x, int y, int except) {
    for (int i = 0; i < MAX_PLAYERS; i++)
        if (i != except && g->pl[i].active && g->pl[i].hp > 0 && g->pl[i].x == x && g->pl[i].y == y) return i;
    return -1;
}

int game_player_count(const Game *g) {
    int n = 0;
    for (int i = 0; i < MAX_PLAYERS; i++) n += g->pl[i].active;
    return n;
}

const char *game_path_name(int path) {
    return path == COSMOS_PATH_DIRECT ? "direct" : path == COSMOS_PATH_RELAY ? "Steam relay" : "path unknown";
}

static const char *who(const Game *g, uint32_t tag) {
    static char buf[4][16];
    static int k;
    int s = game_slot_of(g, tag);
    if (tag == g->my_tag) return "you";
    k = (k + 1) & 3;
    snprintf(buf[k], sizeof buf[k], s >= 0 ? "P%d" : "someone", s + 1);
    return buf[k];
}

/* Nearest free open tile to (x, y), searching outward. */
static void free_spot_near(const Game *g, int x, int y, int *ox, int *oy) {
    for (int r = 0; r < 8; r++)
        for (int dy = -r; dy <= r; dy++)
            for (int dx = -r; dx <= r; dx++) {
                int tx = x + dx, ty = y + dy;
                if (level_walkable(&g->lv, tx, ty) && g->lv.t[ty][tx] != T_STAIRS && game_monster_at(g, tx, ty) < 0 &&
                    player_at(g, tx, ty, -1) < 0) {
                    *ox = tx;
                    *oy = ty;
                    return;
                }
            }
    *ox = x;
    *oy = y;
}

/* ---- peers ---- */

static Peer *peer_entry(Game *g, uint32_t peer, int add) {
    Peer *free_slot = NULL;
    for (int i = 0; i < MAX_PLAYERS; i++) {
        if (g->peers[i].peer == peer) return &g->peers[i];
        if (!g->peers[i].peer && !free_slot) free_slot = &g->peers[i];
    }
    if (!add || !free_slot) return NULL;
    memset(free_slot, 0, sizeof *free_slot);
    free_slot->peer = peer;
    free_slot->path = COSMOS_PATH_UNKNOWN; /* the SDK reports it right after the join */
    return free_slot;
}

static void send_hello(Game *g, uint32_t to) {
    uint8_t m[5] = {MSG_HELLO};
    put_u32(m + 1, g->my_tag);
    cosmos_send(g->c, to, CH_GAME, m, sizeof m, 1);
}

/* ---- async plane: notes and graves ---- */

/* Room index + offset -> a tile on this map, or -1 if not this depth. */
static void place_spot(const Game *g, int depth, int room, int dx, int dy, int *x, int *y) {
    const Room *r;
    *x = *y = -1;
    if (!g->have_level || g->lv.depth != depth || g->lv.n_rooms == 0) return;
    r = &g->lv.rooms[room % g->lv.n_rooms];
    *x = r->x + (dx < r->w ? dx : r->w - 1);
    *y = r->y + (dy < r->h ? dy : r->h - 1);
}

static void place_mark(const Game *g, Mark *m) { place_spot(g, m->depth, m->room, m->dx, m->dy, &m->x, &m->y); }

/* A tile as [room, dx, dy] for a record. */
static void spot_bytes(const Game *g, int x, int y, uint8_t out[3]) {
    int room = level_room_at(&g->lv, x, y), dx = x - g->lv.rooms[room].x, dy = y - g->lv.rooms[room].y;
    out[0] = (uint8_t)room;
    out[1] = (uint8_t)(dx < 0 ? 0 : dx);
    out[2] = (uint8_t)(dy < 0 ? 0 : dy);
}

static void on_lobby(Game *g, const cosmos_event_t *ev) {
    Lobby *l = NULL;
    char code[COSMOS_CODE_MAX];
    size_t n = ev->len - 3;
    int players = ev->data[0], depth = get_u16(ev->data + 1);
    if (n != 9 || players < 1 || players > MAX_PLAYERS || depth < 1) return; /* XXXX-XXXX */
    for (size_t i = 0; i < n; i++) {
        char c = (char)ev->data[3 + i];
        if (i == 4 ? c != '-' : !strchr("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) || !c) return;
        code[i] = c;
    }
    code[n] = 0;
    for (int i = 0; i < g->n_lobbies && !l; i++)
        if (g->lobbies[i].pub_len == ev->publisher_len && !memcmp(g->lobbies[i].pub, ev->publisher, ev->publisher_len)) l = &g->lobbies[i];
    if (!l && g->n_lobbies < MAX_LOBBIES) l = &g->lobbies[g->n_lobbies++];
    if (!l) { /* full: replace the stalest, but never a listing still being refreshed */
        l = &g->lobbies[0];
        for (int i = 1; i < MAX_LOBBIES; i++) if (g->lobbies[i].seen < l->seen) l = &g->lobbies[i];
        if (g->now - l->seen < LOBBY_EVERY + 5) return;
    }
    memcpy(l->pub, ev->publisher, ev->publisher_len);
    l->pub_len = ev->publisher_len;
    copy_str(l->code, sizeof l->code, code);
    l->players = players;
    l->depth = depth;

    l->seen = g->now;
}

static void on_ghost(Game *g, const cosmos_event_t *ev) {
    Ghost *gh = NULL;
    uint32_t tag;
    if (ev->len != 7) return;
    tag = get_u32(ev->data + 3);
    if ((ev->publisher_len == g->my_id_len && !memcmp(ev->publisher, g->my_id, g->my_id_len)) || game_slot_of(g, tag) >= 0)
        return; /* me, or someone in my own run: they are real, not ghosts */
    for (int i = 0; i < g->n_ghosts && !gh; i++)
        if (g->ghosts[i].pub_len == ev->publisher_len && !memcmp(g->ghosts[i].pub, ev->publisher, ev->publisher_len)) gh = &g->ghosts[i];
    if (!gh && g->n_ghosts < MAX_GHOSTS) gh = &g->ghosts[g->n_ghosts++];
    if (!gh) { /* full: replace the stalest */
        gh = &g->ghosts[0];
        for (int i = 1; i < MAX_GHOSTS; i++) if (g->ghosts[i].seen < gh->seen) gh = &g->ghosts[i];
    }
    memcpy(gh->pub, ev->publisher, ev->publisher_len);
    gh->pub_len = ev->publisher_len;
    gh->tag = tag;
    gh->depth = g->marks_depth;
    gh->room = ev->data[0];
    gh->dx = ev->data[1];
    gh->dy = ev->data[2];
    gh->seen = g->now;
    place_spot(g, gh->depth, gh->room, gh->dx, gh->dy, &gh->x, &gh->y);
}

static void depth_key(char *out, size_t cap, int depth) { snprintf(out, cap, "d%d", depth); }

static Mark *mark_slot(Game *g, int grave, const uint8_t *pub, size_t len) {
    for (int i = 0; i < g->n_marks; i++)
        if (g->marks[i].grave == grave && g->marks[i].pub_len == len && !memcmp(g->marks[i].pub, pub, len)) return &g->marks[i];
    return g->n_marks < MAX_MARKS ? &g->marks[g->n_marks++] : &g->marks[rng_next(&g->rng) % MAX_MARKS];
}

static void on_record(Game *g, const cosmos_event_t *ev) {
    char key[16];
    int grave;
    Mark *m;
    if (ev->error != COSMOS_OK || !ev->data || !ev->record_kind || !ev->record_key || ev->len < 4 ||
        ev->len > 3 + NOTE_MAX || ev->publisher_len > COSMOS_PEER_ID_MAX)
        return;
    if (!strcmp(ev->record_kind, "lobby")) {
        if (g->browsing && !strcmp(ev->record_key, "open")) on_lobby(g, ev);
        return;
    }
    depth_key(key, sizeof key, g->marks_depth);
    if (strcmp(ev->record_key, key)) return; /* an older depth's answer */
    if (!strcmp(ev->record_kind, "ghost")) {
        on_ghost(g, ev);
        return;
    }
    if (!strcmp(ev->record_kind, "note")) grave = 0;
    else if (!strcmp(ev->record_kind, "grave")) grave = 1;
    else return;
    m = mark_slot(g, grave, ev->publisher, ev->publisher_len);
    memset(m, 0, sizeof *m);
    m->grave = grave;
    memcpy(m->pub, ev->publisher, ev->publisher_len);
    m->pub_len = ev->publisher_len;
    m->depth = g->marks_depth;
    m->room = ev->data[0];
    m->dx = ev->data[1];
    m->dy = ev->data[2];
    copy_text(m->text, sizeof m->text, ev->data + 3, ev->len - 3);
    place_mark(g, m);
}

void game_watch_depth(Game *g, int depth) {
    char key[16];
    depth_key(key, sizeof key, depth);
    if (depth != g->marks_depth) {
        if (g->sub_note > 0) cosmos_record_unsubscribe(g->c, g->sub_note);
        if (g->sub_grave > 0) cosmos_record_unsubscribe(g->c, g->sub_grave);
        if (g->sub_ghost > 0) cosmos_record_unsubscribe(g->c, g->sub_ghost);
        g->n_marks = 0;
        g->n_ghosts = 0;
        g->marks_depth = depth;
        g->sub_note = cosmos_record_subscribe(g->c, "note", key);
        g->sub_grave = cosmos_record_subscribe(g->c, "grave", key);
        g->sub_ghost = cosmos_record_subscribe(g->c, "ghost", key); /* live only: no query */
    }
    g->req += 2;
    cosmos_record_query(g->c, "note", key, g->req);
    cosmos_record_query(g->c, "grave", key, g->req + 1);
}

/* Record payload for a mark at my spot: [room, dx, dy, text]. */
static int start_put(Game *g, const char *kind, int x, int y, int depth, const char *text) {
    Job *j = &g->put;
    Mark *m = &g->put_mark;
    size_t n = strlen(text);
    if (j->thread || n == 0 || !g->have_level) return 0;
    if (n > NOTE_MAX) n = NOTE_MAX;
    memset(m, 0, sizeof *m);
    m->grave = !strcmp(kind, "grave");
    m->depth = depth;
    spot_bytes(g, x, y, j->data);
    m->room = j->data[0];
    m->dx = j->data[1];
    m->dy = j->data[2];
    memcpy(m->text, text, n);
    memcpy(m->pub, g->my_id, g->my_id_len);
    m->pub_len = g->my_id_len;
    memcpy(j->data + 3, text, n);
    j->len = 3 + n;
    j->ttl = RECORD_TTL;
    copy_str(j->kind, sizeof j->kind, kind);
    depth_key(j->key, sizeof j->key, depth);
    return job_start(g, j, JOB_PUT);
}

int game_put_note(Game *g, const char *text) {
    Player *me = game_me(g);
    if (!me || !start_put(g, "note", g->me_x, g->me_y, g->lv.depth, text)) return 0;
    copy_str(g->status, sizeof g->status, "writing the note...");
    return 1;
}

/* ---- sync plane: level, snapshot, events ---- */

static void apply_level(Game *g, uint32_t seed, int depth) {
    level_generate(&g->lv, seed, depth);
    g->have_level = 1;
    g->tick = 0;
    g->n_pend = 0;
    memset(g->seen, 0, sizeof g->seen);
    for (int i = 0; i < g->n_marks; i++) place_mark(g, &g->marks[i]);
    game_watch_depth(g, depth);
    for (int i = 0; i < g->n_ghosts; i++) {
        Ghost *gh = &g->ghosts[i];
        place_spot(g, gh->depth, gh->room, gh->dx, gh->dy, &gh->x, &gh->y);
    }
    log_add(g, depth == 1 ? "A new descent begins. Depth 1." : "Down the stairs: depth %d.", depth);
}

static void send_level(Game *g, uint32_t to) {
    uint8_t m[7] = {MSG_LEVEL};
    put_u32(m + 1, g->lv.seed);
    put_u16(m + 5, (uint16_t)g->lv.depth);
    cosmos_send(g->c, to, CH_GAME, m, sizeof m, 1);
}

static size_t build_snap(const Game *g, uint8_t *m) {
    size_t n = 0;
    uint8_t taken = 0, *np, *nm;
    m[n++] = MSG_SNAP;
    put_u32(m + n, g->tick); n += 4;
    put_u32(m + n, g->lv.seed); n += 4;
    put_u16(m + n, (uint16_t)g->lv.depth); n += 2;
    for (int i = 0; i < g->lv.n_items; i++) taken |= (uint8_t)(g->lv.items[i].taken << i);
    m[n++] = taken;
    np = &m[n++];
    *np = 0;
    for (int i = 0; i < MAX_PLAYERS; i++) {
        const Player *p = &g->pl[i];
        if (!p->active) continue;
        m[n++] = (uint8_t)i;
        put_u32(m + n, p->tag); n += 4;
        m[n++] = (uint8_t)p->x;
        m[n++] = (uint8_t)p->y;
        m[n++] = (uint8_t)p->hp;
        put_u16(m + n, p->ack); n += 2;
        (*np)++;
    }
    nm = &m[n++];
    *nm = 0;
    for (int i = 0; i < g->lv.n_mon; i++) {
        const Monster *o = &g->lv.mon[i];
        if (!o->alive) continue;
        m[n++] = (uint8_t)i;
        m[n++] = (uint8_t)o->x;
        m[n++] = (uint8_t)o->y;
        m[n++] = (uint8_t)o->hp;
        (*nm)++;
    }
    return n;
}

#define SNAP_MAX (13 + MAX_PLAYERS * 10 + 1 + MAX_MONSTERS * 4)

static void send_snap(Game *g, uint32_t to, int reliable) {
    uint8_t m[SNAP_MAX];
    cosmos_send(g->c, to, CH_GAME, m, build_snap(g, m), reliable);
}

static int seq_after(uint16_t a, uint16_t b) { return (int16_t)(a - b) > 0; }

/* My shown spot = host's spot + my intents it has not applied yet. */
static void predict_step(Game *g, int act) {
    Player *me = game_me(g);
    int x, y;
    if (!me || me->hp <= 0 || act >= 8) return;
    x = g->me_x + DIR_X[act];
    y = g->me_y + DIR_Y[act];
    if (game_monster_at(g, x, y) >= 0 || !level_walkable(&g->lv, x, y)) return; /* a bump, or a wall */
    if (player_at(g, x, y, (int)(me - g->pl)) >= 0) return;
    g->me_x = x;
    g->me_y = y;
}

static void reconcile(Game *g) {
    Player *me = game_me(g);
    int k = 0;
    if (!me) return;
    for (int i = 0; i < g->n_pend; i++)
        if (seq_after(g->pend_seq[i], me->ack)) { g->pend[k] = g->pend[i]; g->pend_seq[k] = g->pend_seq[i]; k++; }
    g->n_pend = k;
    g->me_x = me->x;
    g->me_y = me->y;
    for (int i = 0; i < g->n_pend; i++) predict_step(g, g->pend[i]);
}

static void apply_snap(Game *g, const uint8_t *d, size_t len) {
    size_t n;
    uint32_t tick;
    int np, nm;
    if (len < 14) return;
    tick = get_u32(d + 1);
    if (!g->have_level || get_u32(d + 5) != g->lv.seed || get_u16(d + 9) != g->lv.depth) {
        /* A newer level than ours: its LEVEL was lost (queue overflow). */
        if (g->have_level && get_u16(d + 9) < g->lv.depth) return;
        apply_level(g, get_u32(d + 5), get_u16(d + 9));
    }
    if (tick <= g->tick) return; /* stale (unreliable can reorder) */
    n = 11;
    for (int i = 0; i < g->lv.n_items; i++) g->lv.items[i].taken = (d[n] >> i) & 1;
    n++;
    np = d[n++];
    if (np > MAX_PLAYERS || len < n + (size_t)np * 10 + 1) return;
    nm = d[n + (size_t)np * 10];
    if (nm > MAX_MONSTERS || len != n + (size_t)np * 10 + 1 + (size_t)nm * 4) return;
    g->tick = tick;
    for (int i = 0; i < MAX_PLAYERS; i++) g->pl[i].active = 0;
    for (int i = 0; i < np; i++, n += 10) {
        Player *p;
        if (d[n] >= MAX_PLAYERS) continue;
        p = &g->pl[d[n]];
        p->active = 1;
        p->tag = get_u32(d + n + 1);
        p->x = d[n + 5] < MAP_W ? d[n + 5] : 0;
        p->y = d[n + 6] < MAP_H ? d[n + 6] : 0;
        p->hp = d[n + 7];
        p->ack = get_u16(d + n + 8);
    }
    n++;
    for (int i = 0; i < g->lv.n_mon; i++) g->lv.mon[i].alive = 0;
    for (int i = 0; i < nm; i++, n += 4) {
        Monster *m;
        if (d[n] >= g->lv.n_mon) continue;
        m = &g->lv.mon[d[n]];
        m->alive = 1;
        m->x = d[n + 1] < MAP_W ? d[n + 1] : 0;
        m->y = d[n + 2] < MAP_H ? d[n + 2] : 0;
        m->hp = d[n + 3];
    }
    reconcile(g);
}

/* Events: the host sends them and applies them itself through here. */
static void on_event(Game *g, const uint8_t *d, size_t len) {
    uint32_t tag;
    int s;
    if (len < 9) return;
    tag = get_u32(d + 2);
    s = game_slot_of(g, tag);
    if (d[1] == EVT_KILL && d[6] < g->lv.n_mon) {
        g->lv.mon[d[6]].alive = 0;
        g->last_kill_tag = tag;
        g->last_kill_id = d[6];
        g->kills_seen++;
        log_add(g, "%s slew the %s.", who(g, tag), MONSTER_KINDS[g->lv.mon[d[6]].type].name);
    } else if (d[1] == EVT_DEATH) {
        char cause[CAUSE_MAX + 1];
        copy_text(cause, sizeof cause, d + 9, len - 9);
        if (s >= 0) g->pl[s].hp = 0;
        g->deaths_seen++;
        log_add(g, "%s fell to %s.", who(g, tag), cause);
        if (tag == g->my_tag) { /* leave a death mark for later runs */
            snprintf(g->grave_queue, sizeof g->grave_queue, "slain by %s at depth %d", cause, g->lv.depth);
            g->grave_x = d[7];
            g->grave_y = d[8];
            g->grave_depth = g->lv.depth;
        }
    } else if (d[1] == EVT_PICKUP && d[6] < g->lv.n_items) {
        g->lv.items[d[6]].taken = 1;
        log_add(g, "%s drank a glow tonic.", who(g, tag));
    }
}

static void send_event(Game *g, int type, uint32_t tag, int a, int b, int c, const char *text) {
    uint8_t m[9 + CAUSE_MAX];
    size_t n = text ? strlen(text) : 0;
    if (n > CAUSE_MAX) n = CAUSE_MAX;
    m[0] = MSG_EVENT;
    m[1] = (uint8_t)type;
    put_u32(m + 2, tag);
    m[6] = (uint8_t)a;
    m[7] = (uint8_t)b;
    m[8] = (uint8_t)c;
    if (n) memcpy(m + 9, text, n);
    cosmos_send(g->c, COSMOS_BROADCAST, CH_GAME, m, 9 + n, 1);
    on_event(g, m, 9 + n);
}

/* ---- host rules ---- */

static void host_start_level(Game *g, uint32_t seed, int depth) {
    int anchor_x, anchor_y;
    const Room *r0;
    apply_level(g, seed, depth);
    r0 = &g->lv.rooms[0];
    anchor_x = r0->x + r0->w / 2;
    anchor_y = r0->y + r0->h / 2;
    for (int i = 0; i < MAX_PLAYERS; i++) {
        Player *p = &g->pl[i];
        if (!p->active) continue;
        p->x = p->y = -1;
        if (depth == 1) p->hp = PLAYER_HP;          /* new run */
        else if (p->hp <= 0) p->hp = PLAYER_HP / 2; /* the fallen get back up */
        if (p->qn) p->ack = p->qseq[p->qn - 1];
        p->qn = 0;
        free_spot_near(g, anchor_x, anchor_y, &p->x, &p->y);
    }
    g->all_dead_at = 0;
    send_level(g, COSMOS_BROADCAST);
    reconcile(g);
}

static Player *host_add_player(Game *g, uint32_t peer, uint32_t tag) {
    int ax = g->lv.rooms[0].x + g->lv.rooms[0].w / 2, ay = g->lv.rooms[0].y + g->lv.rooms[0].h / 2;
    Player *p = NULL;
    for (int i = 0; i < MAX_PLAYERS; i++) {
        if (g->pl[i].active && g->pl[i].peer == peer) return &g->pl[i];
        if (!g->pl[i].active && !p) p = &g->pl[i];
    }
    if (!p || tag == 0 || game_slot_of(g, tag) >= 0) return NULL; /* tags must be unique */
    for (int i = 0; i < MAX_PLAYERS; i++) /* join next to someone alive */
        if (g->pl[i].active && g->pl[i].hp > 0) { ax = g->pl[i].x; ay = g->pl[i].y; break; }
    memset(p, 0, sizeof *p);
    p->active = 1;
    p->peer = peer;
    p->tag = tag;
    p->hp = PLAYER_HP;
    free_spot_near(g, ax, ay, &p->x, &p->y);
    log_add(g, "%s entered the depths.", who(g, tag));
    return p;
}

void game_hurt(Game *g, int slot, int dmg, const char *cause) {
    Player *p;
    if (!g->is_host || slot < 0 || slot >= MAX_PLAYERS) return;
    p = &g->pl[slot];
    if (!p->active || p->hp <= 0) return;
    p->hp -= dmg;
    if (p->hp <= 0) {
        p->hp = 0;
        send_event(g, EVT_DEATH, p->tag, 0, p->x, p->y, cause);
    }
}

static void host_act(Game *g, Player *p, int act) {
    int x, y, m;
    if (act == ACT_DESCEND) {
        if (g->lv.t[p->y][p->x] == T_STAIRS) host_start_level(g, rng_next(&g->rng), g->lv.depth + 1);
        return;
    }
    x = p->x + DIR_X[act];
    y = p->y + DIR_Y[act];
    if ((m = game_monster_at(g, x, y)) >= 0) { /* bump to attack */
        Monster *o = &g->lv.mon[m];
        o->hp -= 2 + (int)(rng_next(&g->rng) % 3);
        if (o->hp <= 0) {
            o->hp = 0;
            send_event(g, EVT_KILL, p->tag, m, o->type, 0, NULL);
        }
        return;
    }
    if (!level_walkable(&g->lv, x, y) || player_at(g, x, y, (int)(p - g->pl)) >= 0) return;
    p->x = x;
    p->y = y;
    for (int i = 0; i < g->lv.n_items; i++) {
        Item *it = &g->lv.items[i];
        if (!it->taken && it->x == x && it->y == y) {
            p->hp = p->hp + POTION_HP > PLAYER_HP ? PLAYER_HP : p->hp + POTION_HP;
            send_event(g, EVT_PICKUP, p->tag, i, 0, 0, NULL);
        }
    }
}

static int sign(int v) { return (v > 0) - (v < 0); }

static int monster_can_enter(const Game *g, int x, int y) {
    return level_walkable(&g->lv, x, y) && game_monster_at(g, x, y) < 0 && player_at(g, x, y, -1) < 0;
}

static void monster_turn(Game *g, int id) {
    Monster *m = &g->lv.mon[id];
    const MonsterKind *k = &MONSTER_KINDS[m->type];
    int best = -1, bd = VIEW + 1;
    if (g->tick % (uint32_t)k->slow) return;
    for (int i = 0; i < MAX_PLAYERS; i++) {
        const Player *p = &g->pl[i];
        int d = abs(p->x - m->x) > abs(p->y - m->y) ? abs(p->x - m->x) : abs(p->y - m->y);
        if (p->active && p->hp > 0 && d < bd && level_los(&g->lv, m->x, m->y, p->x, p->y)) { bd = d; best = i; }
    }
    if (best < 0) return;
    if (bd <= 1) {
        char cause[CAUSE_MAX + 1];
        snprintf(cause, sizeof cause, "a %s", k->name);
        game_hurt(g, best, k->dmg, cause);
        return;
    }
    {
        int sx = sign(g->pl[best].x - m->x), sy = sign(g->pl[best].y - m->y);
        int tries[3][2] = {{sx, sy}, {sx, 0}, {0, sy}};
        for (int t = 0; t < 3; t++) {
            int x = m->x + tries[t][0], y = m->y + tries[t][1];
            if ((tries[t][0] || tries[t][1]) && monster_can_enter(g, x, y)) { m->x = x; m->y = y; break; }
        }
    }
}

static void host_tick(Game *g, double now) {
    int alive = 0, active = 0;
    g->tick++;
    for (int i = 0; i < MAX_PLAYERS; i++) {
        Player *p = &g->pl[i];
        if (!p->active || !p->qn) continue;
        int act = p->q[0];
        p->ack = p->qseq[0];
        p->qn--;
        memmove(p->q, p->q + 1, (size_t)p->qn);
        memmove(p->qseq, p->qseq + 1, sizeof p->qseq[0] * (size_t)p->qn);
        if (p->hp > 0) host_act(g, p, act);
        if (act == ACT_DESCEND && g->tick == 0) return; /* a new level started this tick */
    }
    if (!g->peaceful)
        for (int i = 0; i < g->lv.n_mon; i++) if (g->lv.mon[i].alive) monster_turn(g, i);
    for (int i = 0; i < MAX_PLAYERS; i++) { active += g->pl[i].active; alive += g->pl[i].active && g->pl[i].hp > 0; }
    if (active && !alive) {
        if (!g->all_dead_at) {
            g->all_dead_at = now + 4;
            log_add(g, "Everyone has fallen. A new descent soon...");
        } else if (now >= g->all_dead_at) {
            host_start_level(g, rng_next(&g->rng), 1);
            return;
        }
    }
    send_snap(g, COSMOS_BROADCAST, 0);
    reconcile(g);
}

int game_input(Game *g, int act) {
    Player *me = game_me(g);
    if (g->state != ST_PLAYING || !me || me->hp <= 0 || act < 0 || act >= ACT_COUNT || g->n_pend >= MAX_PENDING) return 0;
    g->seq++;
    g->pend[g->n_pend] = (uint8_t)act;
    g->pend_seq[g->n_pend++] = g->seq;
    predict_step(g, act);
    if (g->is_host) {
        me->q[me->qn] = (uint8_t)act;
        me->qseq[me->qn++] = g->seq;
    } else {
        uint8_t m[6] = {MSG_INTENT};
        put_u16(m + 1, g->seq);
        m[3] = (uint8_t)act;
        put_u16(m + 4, (uint16_t)g->lv.seed);
        cosmos_send(g->c, g->host_peer, CH_GAME, m, sizeof m, 1);
    }
    return 1;
}

/* ---- lifecycle ---- */

Game *game_new(const DepthsConfig *cfg, char *err, size_t cap) {
    cosmos_config_t cc;
    char dll[300];
    int r;
    Game *g = calloc(1, sizeof *g);
    if (!g) { snprintf(err, cap, "out of memory"); return NULL; }
    g->rng = plat_seed() | 1;
    g->my_tag = rng_next(&g->rng) | 1;
    g->marks_depth = -1;

    memset(&cc, 0, sizeof cc);
    cc.game_id = cfg->test ? GAME_ID_TEST : GAME_ID;
    cc.listen = cfg->listen[0] ? cfg->listen : NULL;
    cc.bootstrap = cfg->bootstrap[0] ? cfg->bootstrap : NULL;
    cc.key_path = cfg->key[0] ? cfg->key : NULL;
    cc.cache_dir = cfg->cache[0] ? cfg->cache : NULL;
    cc.lan = cfg->lan;
    cc.steam_app_id = cfg->app_id;
    plat_exe_dir(dll, sizeof dll);
    strncat(dll, "steam_api64.dll", sizeof dll - strlen(dll) - 1);
    cc.steam = cfg->steam >= 0 ? cfg->steam : plat_file_exists(dll);
    g->steam_on = cc.steam;
    g->c = cosmos_init(&cc);
    if (!g->c) {
        snprintf(err, cap, "cosmos_init: %s", cosmos_last_error());
        free(g);
        return NULL;
    }
    r = cosmos_peer_id(g->c, 0, g->my_id, sizeof g->my_id);
    g->my_id_len = r > 0 ? (size_t)r : 0;
    if (cfg->addr_file[0]) {
        char addrs[1024];
        FILE *f = fopen(cfg->addr_file, "w");
        if (f && cosmos_listen_addrs(g->c, addrs, sizeof addrs) >= 0) fputs(addrs, f);
        if (f) fclose(f);
    }
    snprintf(g->status, sizeof g->status, "ready (Steam path %s)", cc.steam ? "on" : "off");
    return g;
}

/* Wait for every worker, then close the node (cosmos_shutdown must not run
 * during another call). */
static int game_reap(void *arg) {
    Game *g = arg;
    Job *jobs[] = {&g->net, &g->put, &g->ghost_put, &g->lobby_put};
    for (size_t i = 0; i < sizeof jobs / sizeof jobs[0]; i++) {
        while (jobs[i]->thread && !plat_thread_done(jobs[i]->thread)) plat_sleep(20);
        plat_thread_join(jobs[i]->thread);
    }
    cosmos_shutdown(g->c);
    free(g);
    return 0;
}

/* A join or put can block for a while: if one is still running after a
 * short wait (menus) a background thread finishes the shutdown so the window
 * never freezes and the node never lingers. */
void game_free(Game *g, double wait) {
    double until;
    int busy;
    if (!g) return;
    g->quitting = 1;
#ifdef __EMSCRIPTEN__
    wait = 0; /* never block the browser main thread: jobs need it to finish */
#endif
    until = plat_now() + wait;
    do {
        Job *jobs[] = {&g->net, &g->put, &g->ghost_put, &g->lobby_put};
        busy = 0;
        for (size_t i = 0; i < sizeof jobs / sizeof jobs[0]; i++) busy |= jobs[i]->thread && !plat_thread_done(jobs[i]->thread);
        if (busy && plat_now() < until) plat_sleep(20);
    } while (busy && plat_now() < until);
    if (busy) {
        void *t = plat_thread(game_reap, g);
        if (t) { plat_thread_detach(t); return; }
#ifdef __EMSCRIPTEN__
        /* no free worker: reaping here would block the main thread the jobs need */
        emscripten_async_call(game_free_later, g, 100);
        return;
#endif
    }
    game_reap(g);
}

void game_host(Game *g) {
    if (g->state != ST_IDLE || !job_start(g, &g->net, JOB_HOST)) return;
    g->is_host = 1;
    g->state = ST_CONNECTING;
    copy_str(g->status, sizeof g->status, "publishing join code...");
}

void game_join(Game *g, const char *code) {
    size_t n = 0;
    if (g->state != ST_IDLE || g->net.thread) return;
    g->browsing = 0;
    for (; *code && n < sizeof g->net.code - 1; code++)
        if (!isspace((unsigned char)*code)) g->net.code[n++] = (char)toupper((unsigned char)*code);
    g->net.code[n] = 0;
    if (!job_start(g, &g->net, JOB_JOIN)) {
        g->state = ST_FAILED;
        copy_str(g->status, sizeof g->status, "join failed: no worker thread");
        return;
    }
    g->state = ST_CONNECTING;
    snprintf(g->status, sizeof g->status, "joining %s...", g->net.code);
}

/* ---- events and frame update ---- */

static void on_message(Game *g, const cosmos_event_t *ev) {
    const uint8_t *d = ev->data;
    Peer *pe = peer_entry(g, ev->peer, 0);
    if (ev->channel != CH_GAME || ev->len < 1) return;
    if (!g->is_host && !g->host_peer) g->host_peer = cosmos_host_peer(g->c);
    if (d[0] == MSG_HELLO && ev->len == 5) {
        if (pe) pe->tag = get_u32(d + 1);
        if (g->is_host && g->have_level) host_add_player(g, ev->peer, get_u32(d + 1));
    } else if (g->is_host) {
        if (d[0] == MSG_INTENT && ev->len == 6 && d[3] < ACT_COUNT && get_u16(d + 4) == (uint16_t)g->lv.seed) {
            for (int i = 0; i < MAX_PLAYERS; i++) {
                Player *p = &g->pl[i];
                if (!p->active || p->peer != ev->peer || p->qn >= MAX_PENDING) continue;
                p->q[p->qn] = d[3];
                p->qseq[p->qn++] = get_u16(d + 1);
            }
        }
    } else if (ev->peer != g->host_peer) {
        return; /* only the host decides the world */
    } else if (d[0] == MSG_LEVEL && ev->len == 7) {
        if (pe) pe->is_host = 1;
        apply_level(g, get_u32(d + 1), get_u16(d + 5));
    } else if (d[0] == MSG_SNAP) {
        apply_snap(g, d, ev->len);
    } else if (d[0] == MSG_EVENT) {
        on_event(g, d, ev->len);
    }
}

static void poll_events(Game *g) {
    cosmos_event_t ev;
    Peer *pe;
    while (cosmos_poll(g->c, &ev) > 0) {
        switch (ev.kind) {
        case COSMOS_EV_PEER_JOINED:
            peer_entry(g, ev.peer, 1);
            send_hello(g, ev.peer);
            if (g->is_host && g->have_level) {
                send_level(g, ev.peer);   /* late joiner: the seed... */
                send_snap(g, ev.peer, 1); /* ...and the current state */
            }
            break;
        case COSMOS_EV_PEER_LEFT:
            if ((pe = peer_entry(g, ev.peer, 0))) {
                log_add(g, "%s left.", who(g, pe->tag));
                memset(pe, 0, sizeof *pe);
            }
            if (g->is_host)
                for (int i = 0; i < MAX_PLAYERS; i++)
                    if (g->pl[i].active && g->pl[i].peer == ev.peer) g->pl[i].active = 0;
            break;
        case COSMOS_EV_MESSAGE: on_message(g, &ev); break;
        case COSMOS_EV_PATH_CHANGED:
            if ((pe = peer_entry(g, ev.peer, 0))) pe->path = ev.path;
            break;
        case COSMOS_EV_RECORD_RESULT:
        case COSMOS_EV_RECORD_UPDATE: on_record(g, &ev); break;
        case COSMOS_EV_SESSION_ENDED:
            g->state = ST_ENDED;
            copy_str(g->status, sizeof g->status, "the host left; the run is over");
            break;
        case COSMOS_EV_ERROR:
            snprintf(g->status, sizeof g->status, "%s: %s", cosmos_error_name(ev.error), ev.message ? ev.message : "");
            break;
        default: break;
        }
    }
}

static void collect_jobs(Game *g) {
    if (job_finished(&g->net)) {
        if (g->net.result != COSMOS_OK) {
            g->state = ST_FAILED;
            snprintf(g->status, sizeof g->status, "%s failed: %s", g->is_host ? "host" : "join", g->net.err);
        } else {
            g->state = ST_PLAYING;
            copy_str(g->code, sizeof g->code, g->net.code);
            copy_str(g->status, sizeof g->status, g->is_host ? "hosting" : "joined");
            if (!g->is_host) g->host_peer = cosmos_host_peer(g->c);
            if (g->is_host) {
                level_generate(&g->lv, 0, 1); /* rooms for the first spawn */
                g->have_level = 1;
                host_add_player(g, 0, g->my_tag);
                host_start_level(g, rng_next(&g->rng), 1);
            }
        }
    }
    if (job_finished(&g->put)) {
        g->puts_done++;
        if (g->put.result != COSMOS_OK) {
            snprintf(g->status, sizeof g->status, "record put failed: %s", g->put.err);
        } else {
            if (g->put_mark.depth == g->marks_depth) {
                Mark *m = mark_slot(g, g->put_mark.grave, g->my_id, g->my_id_len);
                *m = g->put_mark;
                place_mark(g, m);
            }
            copy_str(g->status, sizeof g->status, g->put_mark.grave ? "your death mark is left behind" : "note placed");
        }
    }
    if (g->grave_queue[0] && !g->put.thread && g->have_level) {
        int depth = g->lv.depth;
        if (g->grave_depth == depth && start_put(g, "grave", g->grave_x, g->grave_y, depth, g->grave_queue)) g->grave_queue[0] = 0;
        else if (g->grave_depth != depth) g->grave_queue[0] = 0; /* the level is gone */
    }
}

void game_browse(Game *g) {
    if (g->state != ST_IDLE || g->browsing) return;
    g->browsing = 1;
    g->n_lobbies = 0;
    g->next_browse = 0;
    g->sub_lobby = cosmos_record_subscribe(g->c, "lobby", "open");
}

/* Browsing: ask again every few seconds; drop listings gone quiet. */
static void browse_tick(Game *g) {
    if (!g->browsing) {
        if (g->sub_lobby > 0) cosmos_record_unsubscribe(g->c, g->sub_lobby);
        g->sub_lobby = 0;
        return;
    }
    for (int i = 0; i < g->n_lobbies; i++)
        if (g->now - g->lobbies[i].seen > LOBBY_SHOW) g->lobbies[i--] = g->lobbies[--g->n_lobbies];
    if (g->now < g->next_browse) return;
    g->next_browse = g->now + 5;
    cosmos_record_query(g->c, "lobby", "open", ++g->req);
}

/* A public host keeps its listing fresh (players, depth). */
static void lobby_tick(Game *g) {
    Job *j = &g->lobby_put;
    size_t n = strlen(g->code);
    job_finished(j);
    if (!g->public_run || !g->is_host || g->state != ST_PLAYING || !g->have_level || g->now < g->next_lobby || j->thread ||
        n != 9)
        return;
    g->next_lobby = g->now + LOBBY_EVERY;
    j->data[0] = (uint8_t)game_player_count(g);
    put_u16(j->data + 1, (uint16_t)g->lv.depth);
    memcpy(j->data + 3, g->code, n);
    j->len = 3 + n;
    j->ttl = LOBBY_TTL;
    copy_str(j->kind, sizeof j->kind, "lobby");
    copy_str(j->key, sizeof j->key, "open");
    job_start(g, j, JOB_PUT);
}

/* While alive, tell other runs on this depth where I am. A failed put
 * (rate limit, no peers yet) just waits for the next one. */
static void ghost_tick(Game *g) {
    Player *me = game_me(g);
    Job *j = &g->ghost_put;
    job_finished(j);
    /* A ghost that arrived before its player showed up in my own run. */
    for (int i = 0; i < g->n_ghosts; i++)
        if (game_slot_of(g, g->ghosts[i].tag) >= 0) g->ghosts[i--] = g->ghosts[--g->n_ghosts];

    if (g->state != ST_PLAYING || !g->have_level || !me || me->hp <= 0 || g->now < g->next_ghost || j->thread) return;
    g->next_ghost = g->now + GHOST_EVERY;
    spot_bytes(g, g->me_x, g->me_y, j->data);
    put_u32(j->data + 3, g->my_tag);
    j->len = 7;
    j->ttl = GHOST_TTL;
    copy_str(j->kind, sizeof j->kind, "ghost");
    depth_key(j->key, sizeof j->key, g->lv.depth);
    job_start(g, j, JOB_PUT);
}

void game_update(Game *g, double now) {
    g->now = now;
    collect_jobs(g);
    poll_events(g);
    ghost_tick(g);
    lobby_tick(g);
    browse_tick(g);

    if (!g->is_host || g->state != ST_PLAYING) return;
    if (now >= g->next_tick) {
        g->next_tick = now - g->next_tick > 0.5 ? now + 1.0 / TICK_HZ : g->next_tick + 1.0 / TICK_HZ;
        host_tick(g, now);
    }
}
