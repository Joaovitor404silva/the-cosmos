/* Headless self-test (--selftest): games in one process on loopback.
 * One host and two joiners by code, then a late fourth joiner, then a
 * fresh instance outside the session that reads the record store.
 * Prints "ok: ..." per check and "SELFTEST OK" (returns 0), or
 * "FAIL ..." (returns 1). */
#include <stdio.h>
#include <string.h>
#include "depths.h"

#define N 4
#define NOTE_TEXT "selftest note: mind the gaunt"
#define CAUSE "a selftest trap"

static Game *g[N], *fresh;
static int kill_id;

static int fail(const char *what) {
    printf("FAIL %s\n", what);
    for (int i = 0; i < N; i++)
        if (g[i]) printf("  game %d: state %d, %d players, status: %s\n", i, g[i]->state, game_player_count(g[i]), g[i]->status);
    return 1;
}

static void pump(void) {
    double now = plat_now();
    for (int i = 0; i < N; i++) if (g[i]) game_update(g[i], now);
    if (fresh) game_update(fresh, now);
}

static int wait_for(int (*done)(void), double secs) {
    double end = plat_now() + secs;
    while (plat_now() < end) {
        pump();
        if (done()) return 1;
        plat_sleep(10);
    }
    return 0;
}

static int playing(int n) {
    for (int i = 0; i < n; i++) if (g[i]->state != ST_PLAYING || game_player_count(g[i]) != n || !game_me(g[i])) return 0;
    return 1;
}
static int three_playing(void) { return playing(3); }
static int four_playing(void) { return playing(4); }

static int same_map(int n) {
    Level ref;
    level_generate(&ref, g[0]->lv.seed, g[0]->lv.depth);
    for (int i = 0; i < n; i++)
        if (!g[i]->have_level || g[i]->lv.seed != ref.seed || level_hash(&g[i]->lv) != level_hash(&ref)) return 0;
    return 1;
}

static Player *host_view(int i) { return &g[0]->pl[game_slot_of(g[0], g[i]->my_tag)]; }

/* Host world and game i agree on every player and every monster. */
static int world_matches(int i) {
    for (int s = 0; s < MAX_PLAYERS; s++) {
        const Player *h = &g[0]->pl[s];
        int k;
        if (!h->active) continue;
        k = game_slot_of(g[i], h->tag);
        if (k < 0 || g[i]->pl[k].x != h->x || g[i]->pl[k].y != h->y || g[i]->pl[k].hp != h->hp) return 0;
    }
    for (int m = 0; m < g[0]->lv.n_mon; m++) {
        const Monster *a = &g[0]->lv.mon[m], *b = &g[i]->lv.mon[m];
        if (a->alive != b->alive || (a->alive && (a->x != b->x || a->y != b->y || a->hp != b->hp))) return 0;
    }
    return 1;
}

static int moved_for_all(void) {
    for (int i = 0; i < 3; i++) if (!world_matches(i)) return 0;
    return game_me(g[1])->x == g[1]->me_x && game_me(g[1])->y == g[1]->me_y;
}

static int monster_placed(void) {
    const Monster *m = &g[2]->lv.mon[kill_id];
    return m->alive && m->hp == 1 && m->x == g[0]->lv.mon[kill_id].x && m->y == g[0]->lv.mon[kill_id].y;
}

static int kill_seen_by_all(void) {
    for (int i = 0; i < 3; i++)
        if (g[i]->lv.mon[kill_id].alive || g[i]->last_kill_id != kill_id || g[i]->last_kill_tag != g[2]->my_tag) return 0;
    return 1;
}

static int late_joiner_synced(void) { return same_map(4) && four_playing() && world_matches(3) && !g[3]->lv.mon[kill_id].alive; }

static int has_mark(Game *x, int grave, const Game *by, const char *text) {
    for (int k = 0; k < x->n_marks; k++) {
        const Mark *m = &x->marks[k];
        if (m->grave == grave && m->pub_len == by->my_id_len && !memcmp(m->pub, by->my_id, by->my_id_len) && strstr(m->text, text))
            return 1;
    }
    return 0;
}

static int put1_done(void) { return g[1]->puts_done > 0; }
static int put3_done(void) { return g[3]->puts_done > 0; }
static int note_live(void) { return has_mark(g[2], 0, g[1], NOTE_TEXT); }
static int note_fresh(void) { return has_mark(fresh, 0, g[1], NOTE_TEXT); }
static int grave_fresh(void) { return has_mark(fresh, 1, g[3], CAUSE); }
static int three_dead(void) { return game_me(g[3]) && game_me(g[3])->hp == 0 && g[3]->deaths_seen > 0; }

/* Query from the fresh instance every 2 s until `found`. */
static int fresh_finds(int (*found)(void)) {
    for (int t = 0; t < 15; t++) {
        game_watch_depth(fresh, g[0]->lv.depth);
        if (wait_for(found, 2)) return 1;
    }
    return 0;
}

int selftest(void) {
    DepthsConfig cfg;
    char err[256], boot[1024];
    int r = 1, dir = -1;
    Player *p;

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("cosmos %s, depths selftest on loopback\n", cosmos_version());
    config_default(&cfg);
    strcpy(cfg.listen, "127.0.0.1");
    cfg.lan = 0;
    cfg.steam = 0;
    for (int i = 0; i < N; i++) {
        g[i] = game_new(&cfg, err, sizeof err);
        if (!g[i]) { printf("FAIL init: %s\n", err); goto out; }
        if (i == 0) {
            if (cosmos_listen_addrs(g[0]->c, boot, sizeof boot) < 0) { fail("listen_addrs"); goto out; }
            strcpy(cfg.bootstrap, boot);
        }
    }
    g[0]->peaceful = 1; /* monsters stand still: the checks move them */

    game_host(g[0]);
    while (g[0]->state == ST_CONNECTING) { pump(); plat_sleep(10); }
    if (g[0]->state != ST_PLAYING) { fail("host"); goto out; }
    printf("host code %s\n", g[0]->code);
    game_join(g[1], g[0]->code);
    game_join(g[2], g[0]->code);
    if (!wait_for(three_playing, 70)) { fail("join"); goto out; }
    if (!same_map(3)) { fail("same map"); goto out; }
    printf("ok: same map from seed %08x on 3 players (hash %08x)\n", (unsigned)g[0]->lv.seed, (unsigned)level_hash(&g[0]->lv));

    /* Player 1 steps into a free tile: predicted at once, then confirmed. */
    p = game_me(g[1]);
    for (int d = 0; d < 8 && dir < 0; d += 2) {
        int x = p->x + DIR_X[d], y = p->y + DIR_Y[d];
        if (level_walkable(&g[1]->lv, x, y) && game_monster_at(g[0], x, y) < 0) {
            int busy = 0;
            for (int s = 0; s < MAX_PLAYERS; s++) busy |= g[0]->pl[s].active && g[0]->pl[s].x == x && g[0]->pl[s].y == y;
            if (!busy) dir = d;
        }
    }
    if (dir < 0 || !game_input(g[1], dir)) { fail("no free step"); goto out; }
    if (g[1]->me_x != p->x + DIR_X[dir] || g[1]->me_y != p->y + DIR_Y[dir]) { fail("prediction"); goto out; }
    if (!wait_for(moved_for_all, 10)) { fail("move sync"); goto out; }
    printf("ok: player 1 move predicted at once, confirmed by host, seen by all\n");

    /* Host puts a 1 HP monster next to player 2; player 2 bumps it. */
    {
        Player *h = host_view(2);
        int x = -1, y = -1;
        dir = -1;
        kill_id = -1;
        for (int k = 0; k < g[0]->lv.n_mon && kill_id < 0; k++) if (g[0]->lv.mon[k].alive) kill_id = k;
        for (int d = 0; d < 8 && dir < 0; d += 2) {
            int nx = h->x + DIR_X[d], ny = h->y + DIR_Y[d], busy = game_monster_at(g[0], nx, ny) >= 0;
            for (int s = 0; s < MAX_PLAYERS; s++) busy |= g[0]->pl[s].active && g[0]->pl[s].x == nx && g[0]->pl[s].y == ny;
            if (level_walkable(&g[0]->lv, nx, ny) && !busy) { x = nx; y = ny; dir = d; }
        }
        if (kill_id < 0 || dir < 0) { fail("no monster or no room"); goto out; }
        g[0]->lv.mon[kill_id].x = x;
        g[0]->lv.mon[kill_id].y = y;
        g[0]->lv.mon[kill_id].hp = 1;
        if (!wait_for(monster_placed, 10)) { fail("monster placement"); goto out; }
        if (!game_input(g[2], dir)) { fail("attack input"); goto out; }
        if (g[2]->me_x != h->x || g[2]->me_y != h->y) { fail("a bump must not move"); goto out; }
    }
    if (!wait_for(kill_seen_by_all, 10)) { fail("kill"); goto out; }
    printf("ok: monster %d killed by player 2, gone for all 3\n", kill_id);

    game_join(g[3], g[0]->code);
    if (!wait_for(late_joiner_synced, 70)) { fail("late join"); goto out; }
    printf("ok: late 4th player got the seed, the dead monster and every position\n");

    if (!game_put_note(g[1], NOTE_TEXT)) { fail("note put start"); goto out; }
    if (!wait_for(put1_done, 40) || g[1]->put.result != COSMOS_OK) { fail("note put"); goto out; }
    if (!wait_for(note_live, 20)) { fail("note subscription"); goto out; }
    printf("ok: note put by player 1, live on player 2 via subscription\n");
    fresh = game_new(&cfg, err, sizeof err);
    if (!fresh) { printf("FAIL fresh init: %s\n", err); goto out; }
    if (!fresh_finds(note_fresh)) { fail("note query"); goto out; }
    printf("ok: note queried back by a fresh instance\n");

    game_hurt(g[0], game_slot_of(g[0], g[3]->my_tag), 999, CAUSE);
    if (!wait_for(three_dead, 10)) { fail("death event"); goto out; }
    if (!wait_for(put3_done, 40) || g[3]->put.result != COSMOS_OK) { fail("grave put"); goto out; }
    if (!fresh_finds(grave_fresh)) { fail("grave query"); goto out; }
    printf("ok: death mark of player 3 queried back by a fresh instance\n");
    r = 0;

out:
    game_free(fresh);
    for (int i = N - 1; i >= 0; i--) game_free(g[i]);
    printf(r ? "SELFTEST FAILED\n" : "SELFTEST OK\n");
    return r;
}
