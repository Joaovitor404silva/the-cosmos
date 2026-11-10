/* Windows helpers: clock, sleep, threads, files. Kept apart because
 * windows.h and raylib.h clash (CloseWindow, Rectangle, DrawText...). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "depths.h"

double plat_now(void) {
    static LARGE_INTEGER freq;
    LARGE_INTEGER t;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t);
    return (double)t.QuadPart / (double)freq.QuadPart;
}

void plat_sleep(int ms) { Sleep((DWORD)ms); }

typedef struct { int (*fn)(void *); void *arg; } Start;

static DWORD WINAPI thread_main(LPVOID p) {
    Start s = *(Start *)p;
    free(p);
    return (DWORD)s.fn(s.arg);
}

void *plat_thread(int (*fn)(void *), void *arg) {
    Start *s = malloc(sizeof *s);
    HANDLE h;
    if (!s) return NULL;
    s->fn = fn;
    s->arg = arg;
    h = CreateThread(NULL, 0, thread_main, s, 0, NULL);
    if (!h) free(s);
    return h;
}

int plat_thread_done(void *t) { return !t || WaitForSingleObject((HANDLE)t, 0) == WAIT_OBJECT_0; }

void plat_thread_join(void *t) {
    if (!t) return;
    WaitForSingleObject((HANDLE)t, INFINITE);
    CloseHandle((HANDLE)t);
}

int plat_file_exists(const char *path) { return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES; }

void plat_exe_dir(char *out, size_t cap) {
    DWORD n = GetModuleFileNameA(NULL, out, (DWORD)cap);
    if (n == 0 || n >= cap) { out[0] = 0; return; }
    while (n > 0 && out[n - 1] != '\\' && out[n - 1] != '/') n--;
    out[n] = 0; /* keeps the trailing slash */
}

uint32_t plat_seed(void) {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return (uint32_t)t.QuadPart ^ (GetCurrentProcessId() << 16) ^ GetTickCount();
}
