/* Cosmos Depths: window, menu, input and drawing (raylib), ASCII style.
 *
 *   cosmos-depths                   menu: H host, J join by code
 *   cosmos-depths --host | --join CODE
 *   cosmos-depths --selftest        headless loopback test, exit 0 / 1
 * Settings: cosmos-depths.ini next to the exe, then --name value flags
 * (listen, bootstrap, lan, steam, key, cache, app-id, addr-file).
 * --join @FILE starts the node and joins once FILE holds a code.
 * Extras: --bot (autoplay), --window X,Y, --shot FILE (save one frame of
 * this window after --shot-after seconds of play, quit 6 s later). */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "raylib.h"
#include "depths.h"

#define CW 16
#define CH 20
#define MAP_X 20
#define MAP_Y 78
#define WIN_W (MAP_X * 2 + MAP_W * CW)
#define LOG_Y (MAP_Y + MAP_H * CH + 8)
#define WIN_H (LOG_Y + LOG_LINES * 18 + 30)
#define SIGHT 8

enum { SCR_MENU, SCR_CODE, SCR_GAME };

static const Color BG = {10, 10, 16, 255};
static const Color WALL = {120, 110, 150, 255};
static const Color FLOOR_C = {70, 70, 96, 255};
static const Color TEXT = {214, 218, 230, 255};
static const Color DIM = {110, 116, 140, 255};
static const Color AMBER = {255, 206, 92, 255};
static const Color NOTE_C = {120, 230, 120, 255};
static const Color GRAVE_C = {170, 180, 210, 255};
static const Color MON_C[3] = {{230, 120, 220, 255}, {255, 140, 60, 255}, {255, 70, 70, 255}};

static Font font;
static uint8_t vis[MAP_H][MAP_W];

static Color tag_color(uint32_t tag) { return ColorFromHSV((float)(tag % 360u), 0.55f, 1.0f); }

static void glyph(int x, int y, int ch, Color c) {
    Vector2 sz = MeasureTextEx(font, TextFormat("%c", ch), CH, 0);
    DrawTextCodepoint(font, ch, (Vector2){MAP_X + x * CW + (CW - sz.x) / 2, (float)(MAP_Y + y * CH)}, CH, c);
}

static void text(const char *s, int x, int y, int size, Color c) { DrawTextEx(font, s, (Vector2){(float)x, (float)y}, (float)size, 0, c); }

/* What any living player sees (shared sight), remembered in g->seen. */
static void compute_sight(Game *g) {
    Player *me = game_me(g);
    memset(vis, 0, sizeof vis);
    for (int i = 0; i < MAX_PLAYERS; i++) {
        const Player *p = &g->pl[i];
        int px = p == me ? g->me_x : p->x, py = p == me ? g->me_y : p->y;
        if (!p->active || (p->hp <= 0 && p != me)) continue;
        for (int y = py - SIGHT; y <= py + SIGHT; y++)
            for (int x = px - SIGHT; x <= px + SIGHT; x++)
                if (x >= 0 && y >= 0 && x < MAP_W && y < MAP_H && (x - px) * (x - px) + (y - py) * (y - py) <= SIGHT * SIGHT + 4 &&
                    level_los(&g->lv, px, py, x, y)) {
                    vis[y][x] = 1;
                    g->seen[y][x] = 1;
                }
    }
}

static int near_floor(const Level *lv, int x, int y) {
    for (int dy = -1; dy <= 1; dy++)
        for (int dx = -1; dx <= 1; dx++)
            if (level_walkable(lv, x + dx, y + dy)) return 1;
    return 0;
}

static const Mark *mark_near(const Game *g, int x, int y) {
    for (int i = 0; i < g->n_marks; i++)
        if (g->marks[i].x >= 0 && abs(g->marks[i].x - x) <= 1 && abs(g->marks[i].y - y) <= 1) return &g->marks[i];
    return NULL;
}

static void draw_map(Game *g, double t) {
    const Level *lv = &g->lv;
    Player *me = game_me(g);
    compute_sight(g);
    for (int y = 0; y < MAP_H; y++)
        for (int x = 0; x < MAP_W; x++) {
            Color c;
            if (!g->seen[y][x]) continue;
            c = vis[y][x] ? (Color){255, 255, 255, 255} : (Color){255, 255, 255, 90};
            if (lv->t[y][x] == T_WALL && near_floor(lv, x, y)) glyph(x, y, '#', ColorTint(WALL, c));
            else if (lv->t[y][x] == T_FLOOR) glyph(x, y, '.', ColorTint(FLOOR_C, c));
            else if (lv->t[y][x] == T_STAIRS) glyph(x, y, '>', ColorTint(AMBER, c));
        }
    for (int i = 0; i < g->n_marks; i++) { /* notes and graves of other runs */
        const Mark *m = &g->marks[i];
        if (m->x < 0 || !g->seen[m->y][m->x]) continue;
        if (m->grave) glyph(m->x, m->y, '+', Fade(GRAVE_C, 0.45f + 0.15f * sinf((float)t * 2)));
        else glyph(m->x, m->y, '?', NOTE_C);
    }
    for (int i = 0; i < lv->n_items; i++)
        if (!lv->items[i].taken && vis[lv->items[i].y][lv->items[i].x]) glyph(lv->items[i].x, lv->items[i].y, '!', SKYBLUE);
    for (int i = 0; i < lv->n_mon; i++) {
        const Monster *m = &lv->mon[i];
        if (m->alive && vis[m->y][m->x]) glyph(m->x, m->y, MONSTER_KINDS[m->type].glyph, MON_C[m->type]);
    }
    for (int i = 0; i < MAX_PLAYERS; i++) {
        const Player *p = &g->pl[i];
        int x = p == me ? g->me_x : p->x, y = p == me ? g->me_y : p->y;
        if (!p->active) continue;
        if (p == me) DrawRectangleLines(MAP_X + x * CW - 1, MAP_Y + y * CH, CW + 2, CH, Fade(WHITE, 0.5f));
        glyph(x, y, p->hp > 0 ? '@' : '%', p->hp > 0 ? tag_color(p->tag) : DIM);
    }
}

static void draw_hud(Game *g, int typing, const char *note) {
    Player *me = game_me(g);
    int x = MAP_X;
    const Mark *mk;
    if (g->state == ST_PLAYING && g->is_host) text(TextFormat("HOSTING   join code  %s", g->code), x, 10, 24, AMBER);
    else if (g->state == ST_PLAYING) text(TextFormat("JOINED  %s", g->code), x, 10, 24, TEXT);
    else if (g->state <= ST_CONNECTING) text("CONNECTING...", x, 10, 24, TEXT);
    else text("NOT IN A RUN  (Enter: menu)", x, 10, 24, TEXT);
    if (g->have_level) {
        const char *s = TextFormat("depth %d   hp %d/%d", g->lv.depth, me ? me->hp : 0, PLAYER_HP);
        text(s, WIN_W - MAP_X - (int)MeasureTextEx(font, s, 24, 0).x, 10, 24, me && me->hp > 0 ? TEXT : (Color){255, 90, 90, 255});
    }
    /* Path per peer from PATH_CHANGED events: direct or Steam relay. */
    for (int i = 0; i < MAX_PLAYERS; i++) {
        const Peer *p = &g->peers[i];
        int s;
        const char *label;
        if (!p->peer) continue;
        s = game_slot_of(g, p->tag);
        label = TextFormat("%s%s: %s", p->is_host ? "host " : "", s >= 0 ? TextFormat("P%d", s + 1) : "peer", game_path_name(p->path));
        DrawCircle(x + 6, 48, 6, p->tag ? tag_color(p->tag) : DIM);
        text(label, x + 16, 39, 18, p->path == COSMOS_PATH_RELAY ? SKYBLUE : TEXT);
        x += (int)MeasureTextEx(font, label, 18, 0).x + 34;
    }
    text(g->status, WIN_W - MAP_X - (int)MeasureTextEx(font, g->status, 16, 0).x, 41, 16, DIM);

    for (int i = 0; i < LOG_LINES; i++) text(g->log[i], MAP_X, LOG_Y + i * 18, 17, i == LOG_LINES - 1 ? TEXT : DIM);
    mk = me ? mark_near(g, g->me_x, g->me_y) : NULL;
    if (mk) {
        const char *s = TextFormat("%s %s", mk->grave ? "A grave:" : "A note:", mk->text);
        int w = (int)MeasureTextEx(font, s, 18, 0).x + 20;
        DrawRectangle(WIN_W - MAP_X - w, LOG_Y, w, 28, (Color){0, 0, 0, 220});
        DrawRectangleLines(WIN_W - MAP_X - w, LOG_Y, w, 28, mk->grave ? GRAVE_C : NOTE_C);
        text(s, WIN_W - MAP_X - w + 10, LOG_Y + 5, 18, mk->grave ? GRAVE_C : NOTE_C);
    }
    if (typing) {
        DrawRectangle(0, WIN_H - 26, WIN_W, 26, (Color){0, 0, 0, 230});
        text(TextFormat("note: %s_   (Enter write, Esc cancel)", note), MAP_X, WIN_H - 23, 18, NOTE_C);
    } else if (me && me->hp <= 0) {
        text("You have fallen. Your grave stays here for later runs. Watching the others.", MAP_X, WIN_H - 23, 18, (Color){255, 120, 120, 255});
    } else {
        text("arrows/WASD move + bump attack   Q E Z C diagonals   Space on > descend   N note   Esc leave", MAP_X, WIN_H - 23, 16, DIM);
    }
}

/* Append typed printable characters to `buf`; Backspace deletes. */
static void type_into(char *buf, size_t cap, int code_only) {
    size_t n = strlen(buf);
    for (int ch = GetCharPressed(); ch; ch = GetCharPressed()) {
        if (ch < 32 || ch > 126 || n + 1 >= cap) continue;
        if (code_only && !(ch == '-' || (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z'))) continue;
        buf[n++] = (char)(code_only && ch >= 'a' && ch <= 'z' ? ch - 32 : ch);
        buf[n] = 0;
    }
    if (IsKeyPressed(KEY_BACKSPACE) && n > 0) buf[n - 1] = 0;
}

/* Keyboard to an action, or -1. */
static int read_action(int pressed_only) {
    static const int keys[][3] = {
        {KEY_UP, KEY_W, ACT_N}, {KEY_DOWN, KEY_S, ACT_S}, {KEY_LEFT, KEY_A, ACT_W}, {KEY_RIGHT, KEY_D, ACT_E},
        {KEY_Q, KEY_KP_7, ACT_NW}, {KEY_E, KEY_KP_9, ACT_NE}, {KEY_Z, KEY_KP_1, ACT_SW}, {KEY_C, KEY_KP_3, ACT_SE},
    };
    for (size_t i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        int on = pressed_only ? IsKeyPressed(keys[i][0]) || IsKeyPressed(keys[i][1]) : IsKeyDown(keys[i][0]) || IsKeyDown(keys[i][1]);
        if (on) return keys[i][2];
    }
    if (IsKeyPressed(KEY_SPACE) || IsKeyPressed(KEY_PERIOD)) return ACT_DESCEND;
    return -1;
}

/* Autoplay (--bot): fight what it sees, else wander between rooms. */
static int bot_action(Game *g) {
    static int goal = -1;
    int best = -1, bd = 99, tx, ty;
    if (g->lv.t[g->me_y][g->me_x] == T_STAIRS && rand() % 40 == 0) return ACT_DESCEND;
    for (int i = 0; i < g->lv.n_mon; i++) {
        const Monster *m = &g->lv.mon[i];
        int d = abs(m->x - g->me_x) > abs(m->y - g->me_y) ? abs(m->x - g->me_x) : abs(m->y - g->me_y);
        if (m->alive && d < bd && d <= SIGHT && level_los(&g->lv, g->me_x, g->me_y, m->x, m->y)) { bd = d; best = i; }
    }
    if (best >= 0) { tx = g->lv.mon[best].x; ty = g->lv.mon[best].y; }
    else {
        const Room *r;
        if (goal < 0 || goal >= g->lv.n_rooms) goal = rand() % g->lv.n_rooms;
        r = &g->lv.rooms[goal];
        tx = r->x + r->w / 2;
        ty = r->y + r->h / 2;
        if (abs(tx - g->me_x) + abs(ty - g->me_y) <= 1) goal = rand() % g->lv.n_rooms;
    }
    { /* breadth-first distances from the target; take the step downhill */
        static short dist[MAP_H][MAP_W];
        static int qx[MAP_W * MAP_H], qy[MAP_W * MAP_H];
        int head = 0, tail = 0, best_d = -1, best_v;
        memset(dist, -1, sizeof dist);
        dist[ty][tx] = 0;
        qx[tail] = tx; qy[tail++] = ty;
        while (head < tail) {
            int x = qx[head], y = qy[head++];
            for (int d = 0; d < 8; d++) {
                int nx = x + DIR_X[d], ny = y + DIR_Y[d];
                if (level_walkable(&g->lv, nx, ny) && dist[ny][nx] < 0) {
                    dist[ny][nx] = (short)(dist[y][x] + 1);
                    qx[tail] = nx; qy[tail++] = ny;
                }
            }
        }
        best_v = dist[g->me_y][g->me_x];
        for (int d = 0; d < 8; d++) {
            int nx = g->me_x + DIR_X[d], ny = g->me_y + DIR_Y[d];
            if (level_walkable(&g->lv, nx, ny) && dist[ny][nx] >= 0 && dist[ny][nx] < best_v) { best_v = dist[ny][nx]; best_d = d; }
        }
        if (best_d >= 0) return best_d;
    }
    goal = -1;
    return -1;
}

int main(int argc, char **argv) {
    DepthsConfig cfg;
    char path[300], code[COSMOS_CODE_MAX] = "", note[NOTE_MAX + 1] = "", err[256] = "", shot[300] = "", join_file[300] = "";
    int screen = SCR_MENU, typing = 0, bot = 0, host_now = 0, wx = -1, wy = -1;
    double shot_after = 8, played = 0, next_step = 0, quit_at = 0;
    Game *g = NULL;

    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--selftest")) return selftest();

    config_default(&cfg);
    plat_exe_dir(path, sizeof path);
    strncat(path, "cosmos-depths.ini", sizeof path - strlen(path) - 1);
    config_load_ini(&cfg, path);
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : "";
        if (!strcmp(a, "--host")) host_now = 1;
        else if (!strcmp(a, "--bot")) bot = 1;
        else if (!strcmp(a, "--join") && *v == '@') { snprintf(join_file, sizeof join_file, "%s", v + 1); i++; }
        else if (!strcmp(a, "--join") && *v) { snprintf(code, sizeof code, "%s", v); i++; }
        else if (!strcmp(a, "--window") && *v) { sscanf(v, "%d,%d", &wx, &wy); i++; }
        else if (!strcmp(a, "--shot") && *v) { snprintf(shot, sizeof shot, "%s", v); i++; }
        else if (!strcmp(a, "--shot-after") && *v) { shot_after = atof(v); i++; }
        else if (!strncmp(a, "--", 2) && *v && config_set(&cfg, a + 2, v)) i++;
        else { fprintf(stderr, "unknown option %s (see README)\n", a); return 2; }
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    srand(plat_seed());
    SetConfigFlags(FLAG_VSYNC_HINT);
    SetTraceLogLevel(LOG_WARNING);
    InitWindow(WIN_W, WIN_H, "Cosmos Depths");
    if (wx >= 0) SetWindowPosition(wx, wy);
    SetExitKey(0);
    SetTargetFPS(60);
    font = plat_file_exists("C:\\Windows\\Fonts\\consola.ttf") ? LoadFontEx("C:\\Windows\\Fonts\\consola.ttf", 40, NULL, 0) : GetFontDefault();
    SetTextureFilter(font.texture, TEXTURE_FILTER_BILINEAR);

    if (host_now || code[0] || join_file[0]) {
        g = game_new(&cfg, err, sizeof err);
        if (g) {
            if (host_now) game_host(g);
            else if (code[0]) game_join(g, code);
            screen = SCR_GAME;
        }
    }

    while (!WindowShouldClose()) {
        double t = GetTime();

        if (screen == SCR_MENU) {
            if (IsKeyPressed(KEY_ESCAPE)) break;
            if (IsKeyPressed(KEY_H) || IsKeyPressed(KEY_J)) {
                int host = IsKeyPressed(KEY_H);
                while (GetCharPressed()) {} /* drop the H/J keystroke */
                if (host && (g = game_new(&cfg, err, sizeof err))) { game_host(g); screen = SCR_GAME; }
                else if (!host) { code[0] = 0; screen = SCR_CODE; }
            }
        } else if (screen == SCR_CODE) {
            type_into(code, sizeof code, 1);
            if (IsKeyPressed(KEY_ESCAPE)) screen = SCR_MENU;
            if (IsKeyPressed(KEY_ENTER) && code[0] && (g = game_new(&cfg, err, sizeof err))) { game_join(g, code); screen = SCR_GAME; }
            else if (IsKeyPressed(KEY_ENTER)) screen = SCR_MENU;
        } else if (typing) {
            type_into(note, sizeof note, 0);
            if (IsKeyPressed(KEY_ESCAPE)) typing = 0;
            if (IsKeyPressed(KEY_ENTER)) { if (note[0]) game_put_note(g, note); typing = 0; }
        } else {
            /* A press acts at once; holding repeats at the tick rate. */
            int act = read_action(1);
            if (act >= 0) next_step = t + 0.3;
            else if (t >= next_step && (act = read_action(0)) >= 0 && act != ACT_DESCEND) next_step = t + 1.0 / TICK_HZ;
            else act = -1;
            if (bot && g->have_level && t >= next_step) { act = bot_action(g); next_step = t + 1.0 / TICK_HZ; }
            if (act >= 0 && g->n_pend < 3) game_input(g, act);
            if (IsKeyPressed(KEY_N) && g->state == ST_PLAYING && game_me(g)) {
                typing = 1;
                note[0] = 0;
                while (GetCharPressed()) {} /* drop the N keystroke */
            }
            if (IsKeyPressed(KEY_ESCAPE) || (g->state >= ST_FAILED && IsKeyPressed(KEY_ENTER))) {
                snprintf(err, sizeof err, "%s", g->status);
                game_free(g); /* waits for a pending join (up to ~30 s) */
                g = NULL;
                screen = SCR_MENU;
            }
        }
        if (g && g->state == ST_IDLE && join_file[0]) { /* --join @FILE */
            char from_file[COSMOS_CODE_MAX] = "";
            FILE *f = fopen(join_file, "r");
            if (f) { if (!fgets(from_file, sizeof from_file, f)) from_file[0] = 0; fclose(f); }
            if (strlen(from_file) >= 9) game_join(g, from_file);
        }
        if (g) {
            int was = g->state;
            game_update(g, plat_now());
            if (g->state >= ST_FAILED && was < ST_FAILED) fprintf(stderr, "%s\n", g->status);
        }
        if (!g && err[0] && host_now) { fprintf(stderr, "%s\n", err); host_now = 0; }
        if (g && g->state == ST_PLAYING && game_me(g)) {
            if (played == 0 && g->is_host) printf("join code %s\n", g->code); /* for scripts */
            if (bot && played < 3 && played + GetFrameTime() >= 3)
                game_put_note(g, TextFormat("P%d was here. Mind the dark.", game_slot_of(g, g->my_tag) + 1));
            played += GetFrameTime();
        }

        BeginDrawing();
        ClearBackground(BG);
        if (screen == SCR_GAME && g) {
            if (g->have_level) draw_map(g, t);
            draw_hud(g, typing, note);
        } else {
            text("COSMOS DEPTHS", 60, 110, 64, AMBER);
            text("a co-op descent for 1-4 players. Notes and graves outlive the run.", 60, 186, 20, DIM);
            if (screen == SCR_MENU) {
                text("[H]  host a run", 60, 270, 30, TEXT);
                text("[J]  join with a code", 60, 320, 30, TEXT);
                text("[Esc] quit", 60, 370, 30, DIM);
            } else {
                text("type the join code, Enter to join, Esc back", 60, 270, 22, DIM);
                DrawRectangleLines(60, 310, 320, 56, TEXT);
                text(TextFormat("%s_", code), 76, 320, 36, AMBER);
            }
            text(err, 60, 450, 18, (Color){255, 120, 120, 255});
            text(TextFormat("cosmos %s", cosmos_version()), 60, WIN_H - 40, 16, DIM);
        }
        EndDrawing();

        if (quit_at > 0 && t >= quit_at) break;
        if (shot[0] && played >= shot_after && quit_at == 0) {
            /* Without the high-DPI flag the frame is the render size, but
             * LoadImageFromScreen reads screen size x DPI scale: crop. */
            Image img = LoadImageFromScreen();
            ImageCrop(&img, (Rectangle){0, (float)(img.height - GetRenderHeight()), (float)GetRenderWidth(), (float)GetRenderHeight()});
            ExportImage(img, shot);
            UnloadImage(img);
            quit_at = t + 6; /* stay a moment so other windows can shoot us too */
        }
    }
    game_free(g);
    if (font.texture.id != GetFontDefault().texture.id) UnloadFont(font);
    CloseWindow();
    return 0;
}
