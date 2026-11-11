/* Browser build of plat.c: emscripten pthreads (Web Workers). */
#include <emscripten.h>
#include <emscripten/threading.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "depths.h"

double plat_now(void) { return emscripten_get_now() / 1000.0; }

void plat_sleep(int ms) {
    if (emscripten_is_main_browser_thread()) {
        double until = emscripten_get_now() + ms; /* the main thread may not block */
        while (emscripten_get_now() < until) {}
    } else {
        usleep((useconds_t)ms * 1000);
    }
}

typedef struct {
    pthread_t id;
    int (*fn)(void *);
    void *arg;
    atomic_int done;
    atomic_int gone; /* 2 = thread ended and handle released: free */
} Thread;

static void *thread_main(void *p) {
    Thread *t = p;
    t->fn(t->arg);
    atomic_store(&t->done, 1);
    if (atomic_fetch_add(&t->gone, 1) == 1) free(t);
    return NULL;
}

void *plat_thread(int (*fn)(void *), void *arg) {
    Thread *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->fn = fn;
    t->arg = arg;
    if (pthread_create(&t->id, NULL, thread_main, t)) { free(t); return NULL; }
    return t;
}

int plat_thread_done(void *p) { return !p || atomic_load(&((Thread *)p)->done); }

void plat_thread_join(void *p) {
    Thread *t = p;
    if (!t) return;
    pthread_join(t->id, NULL);
    if (atomic_fetch_add(&t->gone, 1) == 1) free(t);
}

void plat_thread_detach(void *p) {
    Thread *t = p;
    if (!t) return;
    pthread_detach(t->id);
    if (atomic_fetch_add(&t->gone, 1) == 1) free(t); /* last one out frees */
}

int plat_file_exists(const char *path) { return access(path, F_OK) == 0; }

void plat_exe_dir(char *out, size_t cap) { if (cap) out[0] = 0; }

uint32_t plat_seed(void) {
    uint32_t s;
    EM_ASM({ HEAPU32[$0 >> 2] = crypto.getRandomValues(new Uint32Array(1))[0]; }, &s);
    return s ^ (uint32_t)emscripten_get_now();
}
