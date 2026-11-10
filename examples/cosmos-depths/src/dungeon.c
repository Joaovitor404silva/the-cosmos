/* Cosmos Depths: level generation from a seed. Pure and deterministic:
 * every peer that gets the same (seed, depth) builds the same level, so
 * the host only sends the seed. */
#include <stdlib.h>
#include <string.h>
#include "depths.h"

const int DIR_X[8] = {0, 1, 1, 1, 0, -1, -1, -1};
const int DIR_Y[8] = {-1, -1, 0, 1, 1, 1, 0, -1};

const MonsterKind MONSTER_KINDS[3] = {
    {'m', "mire mote", 3, 1, 1},     /* weak, quick */
    {'k', "cinder kit", 6, 2, 2},    /* middling */
    {'W', "deep warden", 12, 4, 3}, /* tough, slow */
};

uint32_t rng_next(uint32_t *s) {
    *s ^= *s << 13;
    *s ^= *s >> 17;
    *s ^= *s << 5;
    return *s;
}

static int rnd(uint32_t *s, int lo, int hi) { return lo + (int)(rng_next(s) % (uint32_t)(hi - lo + 1)); }

int level_walkable(const Level *lv, int x, int y) {
    return x >= 0 && y >= 0 && x < MAP_W && y < MAP_H && lv->t[y][x] != T_WALL;
}

static int overlaps(const Level *lv, Room r) {
    for (int i = 0; i < lv->n_rooms; i++) {
        const Room *o = &lv->rooms[i];
        if (r.x - 1 < o->x + o->w && o->x - 1 < r.x + r.w && r.y - 1 < o->y + o->h && o->y - 1 < r.y + r.h) return 1;
    }
    return 0;
}

static void carve(Level *lv, int x0, int y0, int x1, int y1) {
    for (int y = y0 < y1 ? y0 : y1; y <= (y0 < y1 ? y1 : y0); y++)
        for (int x = x0 < x1 ? x0 : x1; x <= (x0 < x1 ? x1 : x0); x++) lv->t[y][x] = T_FLOOR;
}

static int occupied(const Level *lv, int x, int y) {
    for (int i = 0; i < lv->n_mon; i++) if (lv->mon[i].x == x && lv->mon[i].y == y) return 1;
    for (int i = 0; i < lv->n_items; i++) if (lv->items[i].x == x && lv->items[i].y == y) return 1;
    return lv->t[y][x] != T_FLOOR;
}

/* A free floor tile in a random room other than the first. */
static void free_spot(const Level *lv, uint32_t *s, int *x, int *y) {
    for (int t = 0; t < 200; t++) {
        const Room *r = &lv->rooms[rnd(s, 1, lv->n_rooms - 1)];
        *x = rnd(s, r->x, r->x + r->w - 1);
        *y = rnd(s, r->y, r->y + r->h - 1);
        if (!occupied(lv, *x, *y)) return;
    }
}

void level_generate(Level *lv, uint32_t seed, int depth) {
    uint32_t s = (seed ^ (uint32_t)depth * 0x9E3779B9u) | 1u;
    memset(lv, 0, sizeof *lv);
    lv->seed = seed;
    lv->depth = depth;

    for (int t = 0; t < 400 && lv->n_rooms < MAX_ROOMS; t++) {
        Room r;
        r.w = rnd(&s, 5, 12);
        r.h = rnd(&s, 4, 7);
        r.x = rnd(&s, 1, MAP_W - r.w - 2);
        r.y = rnd(&s, 1, MAP_H - r.h - 2);
        if (!overlaps(lv, r)) lv->rooms[lv->n_rooms++] = r;
    }
    for (int i = 0; i < lv->n_rooms; i++) {
        const Room *r = &lv->rooms[i];
        carve(lv, r->x, r->y, r->x + r->w - 1, r->y + r->h - 1);
        if (i > 0) { /* L-shaped corridor from the previous room's centre */
            const Room *p = &lv->rooms[i - 1];
            int ax = p->x + p->w / 2, ay = p->y + p->h / 2, bx = r->x + r->w / 2, by = r->y + r->h / 2;
            if (rng_next(&s) & 1) { carve(lv, ax, ay, bx, ay); carve(lv, bx, ay, bx, by); }
            else { carve(lv, ax, ay, ax, by); carve(lv, ax, by, bx, by); }
        }
    }
    {
        const Room *last = &lv->rooms[lv->n_rooms - 1];
        lv->t[last->y + last->h / 2][last->x + last->w / 2] = T_STAIRS;
    }

    lv->n_mon = 3 + depth * 2;
    if (lv->n_mon > MAX_MONSTERS) lv->n_mon = MAX_MONSTERS;
    for (int i = 0; i < lv->n_mon; i++) {
        Monster *m = &lv->mon[i];
        int roll = rnd(&s, 0, 9) + depth;
        m->x = m->y = -1; /* not placed yet: occupied() skips it */
        m->type = roll >= 10 ? 2 : roll >= 5 ? 1 : 0;
        m->hp = MONSTER_KINDS[m->type].hp;
        m->alive = 1;
        free_spot(lv, &s, &m->x, &m->y);
    }
    lv->n_items = 2;
    for (int i = 0; i < lv->n_items; i++) {
        lv->items[i].x = lv->items[i].y = -1;
        free_spot(lv, &s, &lv->items[i].x, &lv->items[i].y);
    }
}

uint32_t level_hash(const Level *lv) {
    uint32_t h = 2166136261u;
#define MIX(v) (h = (h ^ (uint32_t)(v)) * 16777619u)
    for (int y = 0; y < MAP_H; y++)
        for (int x = 0; x < MAP_W; x++) MIX(lv->t[y][x]);
    MIX(lv->n_rooms);
    for (int i = 0; i < lv->n_rooms; i++) { MIX(lv->rooms[i].x); MIX(lv->rooms[i].y); MIX(lv->rooms[i].w); MIX(lv->rooms[i].h); }
    for (int i = 0; i < lv->n_items; i++) { MIX(lv->items[i].x); MIX(lv->items[i].y); }
#undef MIX
    return h;
}

int level_room_at(const Level *lv, int x, int y) {
    int best = 0, bd = 1 << 30;
    for (int i = 0; i < lv->n_rooms; i++) {
        const Room *r = &lv->rooms[i];
        int d = abs(r->x + r->w / 2 - x) + abs(r->y + r->h / 2 - y);
        if (x >= r->x && y >= r->y && x < r->x + r->w && y < r->y + r->h) return i;
        if (d < bd) { bd = d; best = i; }
    }
    return best;
}

/* Bresenham line; every tile between the ends must be open. */
int level_los(const Level *lv, int x0, int y0, int x1, int y1) {
    int dx = abs(x1 - x0), dy = -abs(y1 - y0), sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1, err = dx + dy;
    for (;;) {
        int e2;
        if (x0 == x1 && y0 == y1) return 1;
        e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 += sx; }
        if (e2 <= dx) { err += dx; y0 += sy; }
        if ((x0 != x1 || y0 != y1) && !level_walkable(lv, x0, y0)) return 0;
    }
}
