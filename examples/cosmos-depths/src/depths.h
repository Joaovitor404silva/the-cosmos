/* Cosmos Depths: shared types. dungeon.c builds levels, game.c runs the
 * rules and the network, main.c draws (raylib), selftest.c runs headless.
 * No raylib.h or windows.h here. */
#ifndef DEPTHS_H
#define DEPTHS_H

#include <stddef.h>
#include <stdint.h>
#include "cosmos.h"

#define GAME_ID "cosmos-depths"
#define GAME_ID_TEST "cosmos-depths-test"
#define MAP_W 60
#define MAP_H 32
#define MAX_ROOMS 10
#define MAX_MONSTERS 32
#define MAX_ITEMS 3
#define MAX_PLAYERS 4
#define MAX_PENDING 8
#define NOTE_MAX 48
#define MAX_MARKS 32
#define MAX_GHOSTS 16
#define GHOST_EVERY 5.0 /* s between ghost puts (2 of the SDK's 10 puts per 10 s) */
#define GHOST_FADE 12.0 /* s a ghost stays visible without news */

#define MAX_LOBBIES 9
#define LOBBY_EVERY 20.0 /* s between a public host's listing puts */
#define LOBBY_SHOW 60.0  /* s a listing stays in the list without news */
#define LOG_LINES 6
#define TICK_HZ 6
#define PLAYER_HP 20

enum { T_WALL, T_FLOOR, T_STAIRS };

/* Player actions (intents). 0..7: step / bump-attack in a direction. */
enum { ACT_N, ACT_NE, ACT_E, ACT_SE, ACT_S, ACT_SW, ACT_W, ACT_NW, ACT_DESCEND, ACT_COUNT };
extern const int DIR_X[8], DIR_Y[8];

typedef struct { int x, y, w, h; } Room;

typedef struct {
    int alive, type, x, y, hp;
} Monster;

typedef struct { int x, y, taken; } Item;

typedef struct {
    uint32_t seed;
    int depth;
    uint8_t t[MAP_H][MAP_W];
    Room rooms[MAX_ROOMS];
    int n_rooms;
    Monster mon[MAX_MONSTERS]; /* index = monster id */
    int n_mon;
    Item items[MAX_ITEMS];
    int n_items;
} Level;

typedef struct {
    char glyph;
    const char *name;
    int hp, dmg, slow; /* slow: acts every `slow` ticks */
} MonsterKind;
extern const MonsterKind MONSTER_KINDS[3];

/* dungeon.c */
void level_generate(Level *lv, uint32_t seed, int depth);
uint32_t level_hash(const Level *lv); /* tiles, rooms, item spots */
int level_walkable(const Level *lv, int x, int y);
int level_room_at(const Level *lv, int x, int y); /* room index, nearest if in a corridor */
int level_los(const Level *lv, int x0, int y0, int x1, int y1);
uint32_t rng_next(uint32_t *s);

/* Settings from flags / cosmos-depths.ini. */
typedef struct {
    char listen[64];
    char bootstrap[1024];
    char key[260];
    char cache[260];
    char addr_file[260];
    int lan;
    int steam; /* -1: on if steam_api64.dll is next to the exe */
    uint32_t app_id;
    int test; /* scripted/test runs: own namespace, never seen by real players */
} DepthsConfig;

typedef struct {
    int active;
    uint32_t tag;     /* random id the player picked; colour + identity */
    int x, y, hp;
    uint16_t ack;     /* last intent seq the host applied */
    /* host only */
    uint32_t peer;    /* 0: the host itself */
    uint8_t q[MAX_PENDING];
    uint16_t qseq[MAX_PENDING];
    int qn;
} Player;

/* A note or a death mark from the record store. */
typedef struct {
    int grave;
    uint8_t pub[COSMOS_PEER_ID_MAX];
    size_t pub_len;
    int depth, room, dx, dy, x, y;
    char text[NOTE_MAX + 1];
} Mark;

typedef struct {
    uint32_t peer;
    uint32_t tag; /* 0 until its hello */
    int path;     /* COSMOS_PATH_* */
    int is_host;
} Peer;

/* Another run's player on this depth, seen through its ghost records. */
typedef struct {
    uint8_t pub[COSMOS_PEER_ID_MAX];
    size_t pub_len;
    uint32_t tag;
    int depth, room, dx, dy, x, y;
    double seen; /* game time of the last record */
} Ghost;

/* A public run in the lobby list. */
typedef struct {
    uint8_t pub[COSMOS_PEER_ID_MAX];
    size_t pub_len;
    char code[COSMOS_CODE_MAX];
    int players, depth;
    double seen;
} Lobby;

/* One blocking cosmos call on a worker thread. */
typedef struct {
    void *thread;
    struct Game *g;
    int what;
    char code[COSMOS_CODE_MAX];
    char kind[16], key[16];
    uint8_t data[128];
    size_t len;
    uint32_t ttl;
    int result;
    char err[160];
} Job;

enum { ST_IDLE, ST_CONNECTING, ST_PLAYING, ST_FAILED, ST_ENDED };

typedef struct Game {
    cosmos_t *c;
    int state, is_host;
    char code[COSMOS_CODE_MAX];
    char status[200];
    uint8_t my_id[COSMOS_PEER_ID_MAX];
    size_t my_id_len;
    uint32_t my_tag, host_peer;
    int steam_on; /* Steam relay path enabled */
    volatile int quitting; /* game_free asked the workers to stop retrying */
    uint32_t rng;

    /* world: authoritative on the host, mirrored from snapshots elsewhere */
    Level lv;
    int have_level;
    Player pl[MAX_PLAYERS];
    uint32_t tick;
    double next_tick, all_dead_at;
    int peaceful; /* host test hook: monsters stand still */

    /* my prediction */
    int me_x, me_y;
    uint16_t seq;
    uint8_t pend[MAX_PENDING];
    uint16_t pend_seq[MAX_PENDING];
    int n_pend;

    Peer peers[MAX_PLAYERS];
    char log[LOG_LINES][96];
    uint8_t seen[MAP_H][MAP_W];

    /* event counters, for the HUD and the self-test */
    uint32_t last_kill_tag;
    int last_kill_id, kills_seen, deaths_seen;

    /* async plane */
    Mark marks[MAX_MARKS];
    int n_marks, marks_depth;
    int sub_note, sub_grave, sub_ghost;
    uint32_t req;
    Job net, put, ghost_put, lobby_put;
    int public_run;  /* host: list this run in the lobby list (code public) */
    int browsing, sub_lobby;
    Lobby lobbies[MAX_LOBBIES];
    int n_lobbies;
    double next_lobby, next_browse;
    Ghost ghosts[MAX_GHOSTS];
    int n_ghosts;
    double now, next_ghost;
    Mark put_mark; /* what the put worker is writing */
    int puts_done;
    char grave_queue[NOTE_MAX + 1]; /* death mark waiting for the put worker */
    int grave_x, grave_y, grave_depth;
} Game;

/* game.c */
Game *game_new(const DepthsConfig *cfg, char *err, size_t cap);
void game_free(Game *g, double wait); /* wait: seconds before a background thread takes over */
void game_host(Game *g);
void game_join(Game *g, const char *code);
void game_browse(Game *g);                  /* fill g->lobbies with public runs */

void game_update(Game *g, double now);
int game_input(Game *g, int act);           /* queue an intent; 0 if full or dead */
int game_put_note(Game *g, const char *text); /* at my spot; 0 if busy */
void game_watch_depth(Game *g, int depth);  /* query notes and graves, subscribe to them and ghosts */

void game_hurt(Game *g, int slot, int dmg, const char *cause); /* host only */
Player *game_me(Game *g);                   /* NULL until the host lists me */
int game_slot_of(const Game *g, uint32_t tag);
int game_monster_at(const Game *g, int x, int y);
int game_player_count(const Game *g);
const char *game_path_name(int path);
void config_default(DepthsConfig *cfg);
int config_set(DepthsConfig *cfg, const char *name, const char *value);
void config_load_ini(DepthsConfig *cfg, const char *path);

/* plat.c (Windows bits kept away from raylib.h) */
double plat_now(void);
void plat_sleep(int ms);
void *plat_thread(int (*fn)(void *), void *arg);
int plat_thread_done(void *t);
void plat_thread_join(void *t);
void plat_thread_detach(void *t); /* let it run; frees the handle */
int plat_file_exists(const char *path);
void plat_exe_dir(char *out, size_t cap);
uint32_t plat_seed(void);

/* selftest.c */
int selftest(void);

#endif
