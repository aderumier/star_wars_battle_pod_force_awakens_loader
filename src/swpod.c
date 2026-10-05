/*
 * swpod - standalone loader for Star Wars Battle Pod (The Force Awakens, ES3X)
 *
 * Built as a drop-in replacement of hasp_windows_x64_100610.dll. Both
 * RSLauncher.exe and SWArcGame-Win64-Shipping.exe import it (by ordinal), so
 * this DLL is loaded into both processes without any injector:
 *   - emulates the HASP HL API (dongle data from OpenParrot StarWars.cpp)
 *   - game: emulates the JVS I/O board behind wajvio_com.dll's COM port by
 *     patching that DLL's kernel32 IAT (CreateFileA/ReadFile/WriteFile/...)
 *   - inputs: XInput pad + keyboard, mapped in swpod.ini (game root dir)
 * Patches for this exe version live in patches_launcher()/patches_game().
 */
#include <windows.h>
#include <stdarg.h>

/* ------------------------------------------------------------------ utils */

static HMODULE g_self;
static char g_root[MAX_PATH];   /* game root dir (parent of Launcher/Binaries) */
static char g_ini[MAX_PATH];
static HANDLE g_log = INVALID_HANDLE_VALUE;
static int g_is_game, g_is_launcher;

static int my_vsnprintf(char *buf, int n, const char *fmt, va_list ap)
{
    return wvsprintfA(buf, fmt, ap); /* user32, max 1024 chars */
}

static void logf(const char *fmt, ...)
{
    char buf[1100];
    va_list ap;
    int n;
    DWORD w;
    SYSTEMTIME t;
    if (g_log == INVALID_HANDLE_VALUE) return;
    GetLocalTime(&t);
    n = wsprintfA(buf, "%02d:%02d:%02d.%03d [%s] ", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds,
                  g_is_game ? "game" : g_is_launcher ? "launcher" : "?");
    va_start(ap, fmt);
    n += my_vsnprintf(buf + n, 1024, fmt, ap);
    va_end(ap);
    buf[n++] = '\n';
    WriteFile(g_log, buf, n, &w, NULL);
}

static int ini_int(const char *sec, const char *key, int def)
{
    return GetPrivateProfileIntA(sec, key, def, g_ini);
}

static void mem_write(void *dst, const void *src, SIZE_T n)
{
    DWORD old;
    VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old);
    memcpy(dst, src, n);
    VirtualProtect(dst, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), dst, n);
}

static void mem_nop(void *dst, SIZE_T n)
{
    BYTE b[32];
    memset(b, 0x90, n);
    mem_write(dst, b, n);
}

/* write bytes at base+rva only if the current bytes match `expect` */
static int patch(const char *what, BYTE *base, DWORD rva, const void *expect, const void *repl, SIZE_T n)
{
    if (memcmp(base + rva, expect, n)) {
        logf("patch %s @%#x: bytes differ, NOT applied", what, rva);
        return 0;
    }
    mem_write(base + rva, repl, n);
    logf("patch %s @%#x applied", what, rva);
    return 1;
}

/* replace an import of module `mod` (NULL = exe), by name or (name==NULL)
 * by ordinal; returns the old pointer */
static void *iat_hook_ex(HMODULE mod, const char *dll, const char *name, WORD ord, void *fn)
{
    BYTE *base = (BYTE *)(mod ? mod : GetModuleHandleA(NULL));
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *imp;
    if (!dir->VirtualAddress) return NULL;
    for (imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + dir->VirtualAddress); imp->Name; imp++) {
        IMAGE_THUNK_DATA *oft, *ft;
        if (lstrcmpiA((char *)(base + imp->Name), dll)) continue;
        oft = (IMAGE_THUNK_DATA *)(base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        ft = (IMAGE_THUNK_DATA *)(base + imp->FirstThunk);
        for (; oft->u1.AddressOfData; oft++, ft++) {
            IMAGE_IMPORT_BY_NAME *ibn;
            void *old;
            if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
                if (name || IMAGE_ORDINAL(oft->u1.Ordinal) != ord) continue;
            } else {
                ibn = (IMAGE_IMPORT_BY_NAME *)(base + oft->u1.AddressOfData);
                if (!name || strcmp((char *)ibn->Name, name)) continue;
            }
            old = (void *)ft->u1.Function;
            mem_write(&ft->u1.Function, &fn, sizeof(fn));
            return old;
        }
    }
    return NULL;
}
#define iat_hook(m, d, n, f) iat_hook_ex(m, d, n, 0, f)

/* ------------------------------------------------------------------- HASP */

#define HASP_STATUS_OK 0
static BYTE hasp_buffer[0xD40];

static void hasp_init(void)
{
    memset(hasp_buffer, 0, sizeof(hasp_buffer));
    hasp_buffer[0x00] = 0x01;
    hasp_buffer[0x13] = 0x01;
    hasp_buffer[0x17] = 0x0A;
    hasp_buffer[0x1B] = 0x04;
    hasp_buffer[0x1C] = 0x3B;
    hasp_buffer[0x1D] = 0x6B;
    hasp_buffer[0x1E] = 0x40;
    hasp_buffer[0x1F] = 0x87;
    hasp_buffer[0x23] = 0x01;
    hasp_buffer[0x27] = 0x0A;
    hasp_buffer[0x2B] = 0x04;
    hasp_buffer[0x2C] = 0x3B;
    hasp_buffer[0x2D] = 0x6B;
    hasp_buffer[0x2E] = 0x40;
    hasp_buffer[0x2F] = 0x87;
    memcpy(hasp_buffer + 0xD00, "274320990002", 12);
    hasp_buffer[0xD3E] = 0x6A;
    hasp_buffer[0xD3F] = 0x95;
}

int __cdecl hasp_login(unsigned feature, const void *vendor, int *handle)
{
    logf("hasp_login feature=%#x", feature);
    if (handle) *handle = 1;
    return HASP_STATUS_OK;
}
int __cdecl hasp_login_scope(unsigned feature, const char *scope, const void *vendor, int *handle)
{
    logf("hasp_login_scope feature=%#x", feature);
    if (handle) *handle = 1;
    return HASP_STATUS_OK;
}
int __cdecl hasp_logout(int h) { return HASP_STATUS_OK; }
int __cdecl hasp_encrypt(int h, void *buf, unsigned len) { return HASP_STATUS_OK; }
int __cdecl hasp_decrypt(int h, void *buf, unsigned len) { return HASP_STATUS_OK; }
int __cdecl hasp_legacy_encrypt(int h, void *buf, unsigned len) { return HASP_STATUS_OK; }
int __cdecl hasp_legacy_decrypt(int h, void *buf, unsigned len) { return HASP_STATUS_OK; }
int __cdecl hasp_get_size(int h, unsigned fileid, unsigned *size)
{
    if (size) *size = sizeof(hasp_buffer);
    return HASP_STATUS_OK;
}
static BYTE *g_game_base;

int __cdecl hasp_read(int h, unsigned fileid, unsigned off, unsigned len, void *buf)
{
    logf("hasp_read fileid=%#x off=%#x len=%#x", fileid, off, len);
    /* without -Language=JPN the game checks the HASP instead of the USB key
     * (game 0x9dbdc0): the serial at 0xd00 must start with the same 6 chars
     * as the runtime-decrypted template at 0x1573d28 ("******22****" on file) */
    if (g_game_base && off <= 0xd00 && off + len >= 0xd0c) {
        const char *tmpl = (const char *)g_game_base + 0x1573d28;
        static int logged;
        int i;
        for (i = 0; i < 12; i++)
            hasp_buffer[0xd00 + i] = (tmpl[i] == '*' || !tmpl[i]) ? '0' : tmpl[i];
        if (!logged++) logf("HASP serial %s", hasp_buffer + 0xd00);
    }
    if (off < sizeof(hasp_buffer)) {
        unsigned n = len;
        if (off + n > sizeof(hasp_buffer)) n = sizeof(hasp_buffer) - off;
        memcpy(buf, hasp_buffer + off, n);
        if (n < len) memset((BYTE *)buf + n, 0, len - n);
    } else
        memset(buf, 0, len);
    return HASP_STATUS_OK;
}
int __cdecl hasp_write(int h, unsigned fileid, unsigned off, unsigned len, const void *buf)
{
    logf("hasp_write fileid=%#x off=%#x len=%#x", fileid, off, len);
    return HASP_STATUS_OK;
}
static char hasp_info_xml[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><hasp_info><hasp><haspid>274320990</haspid></hasp></hasp_info>";
int __cdecl hasp_get_sessioninfo(int h, const char *fmt, char **info)
{
    if (info) *info = hasp_info_xml;
    return HASP_STATUS_OK;
}
int __cdecl hasp_get_info(const char *scope, const char *fmt, const void *vendor, char **info)
{
    if (info) *info = hasp_info_xml;
    return HASP_STATUS_OK;
}
void __cdecl hasp_free(char *info) {}
int __cdecl hasp_get_rtc(int h, unsigned long long *t) { if (t) *t = 0; return HASP_STATUS_OK; }
int __cdecl hasp_datetime_to_hasptime(unsigned d, unsigned mo, unsigned y, unsigned h, unsigned mi, unsigned s, unsigned long long *t) { if (t) *t = 0; return HASP_STATUS_OK; }
int __cdecl hasp_hasptime_to_datetime(unsigned long long t, unsigned *d, unsigned *mo, unsigned *y, unsigned *h, unsigned *mi, unsigned *s) { return HASP_STATUS_OK; }
int __cdecl hasp_legacy_set_idletime(int h, unsigned short t) { return HASP_STATUS_OK; }
int __cdecl hasp_legacy_set_rtc(int h, unsigned long long t) { return HASP_STATUS_OK; }
int __cdecl hasp_update(const char *u, char **ack) { if (ack) *ack = NULL; return HASP_STATUS_OK; }
int __cdecl hasp_get_trace(char **t) { if (t) *t = NULL; return HASP_STATUS_OK; }
int __cdecl hasp_login_port(unsigned f, const char *p, const void *v, int *h) { if (h) *h = 1; return HASP_STATUS_OK; }
int __cdecl hasp_enable_trace(unsigned l, const char *p) { return HASP_STATUS_OK; }
int __cdecl hasp_login_ex(void) { return HASP_STATUS_OK; }
int __cdecl hasp_get_version(unsigned *ma, unsigned *mi, unsigned *bs, unsigned *bn, const void *v)
{
    if (ma) *ma = 4;
    if (mi) *mi = 0;
    if (bs) *bs = 0;
    if (bn) *bn = 0;
    return HASP_STATUS_OK;
}
int __cdecl hasp_detach(void) { return HASP_STATUS_OK; }

/* ------------------------------------------------------------------ input */

/* digital inputs */
enum { IN_TEST, IN_SERVICE, IN_COIN, IN_START, IN_TRIGGER, IN_WEAPON, IN_VIEW,
       IN_MENU_UP, IN_MENU_DOWN, IN_ENTER, IN_COUNT };
static const char *in_names[IN_COUNT] = { "Test", "Service", "Coin", "Start", "Trigger", "Weapon",
                                          "View", "MenuUp", "MenuDown", "Enter" };
/* defaults: keyboard VK | (xinput button << 16) */
static const int in_def_key[IN_COUNT] = { VK_F2, VK_F1, '5', '1', VK_SPACE, VK_CONTROL, 'V',
                                          VK_HOME, VK_END, VK_RETURN };
static const int in_def_pad[IN_COUNT] = { 0, 0, 0x0020, 0, 0, 0, 0, 0, 0, 0 };
static int in_key[IN_COUNT], in_pad[IN_COUNT];

typedef struct { WORD wButtons; BYTE bLeftTrigger, bRightTrigger; SHORT sThumbLX, sThumbLY, sThumbRX, sThumbRY; } XPAD;
typedef struct { DWORD dwPacketNumber; XPAD Gamepad; } XINSTATE;
typedef DWORD (WINAPI *XInputGetState_t)(DWORD, XINSTATE *);
static XInputGetState_t real_XInputGetState;
static int pad_index, pad_deadzone, pad_stick_dz;

static struct {
    BYTE dig[IN_COUNT];
    BYTE throttle, x, y;    /* 0x00..0xff, 0x80 = center */
    int coins;
} io;
static int coin_prev;
static int axis_kbd_speed;

static void input_config(void)
{
    int i;
    for (i = 0; i < IN_COUNT; i++) {
        in_key[i] = ini_int("Keyboard", in_names[i], in_def_key[i]);
        in_pad[i] = ini_int("XInput", in_names[i], in_def_pad[i]);
    }
    pad_index = ini_int("XInput", "PadIndex", 0);
    pad_deadzone = ini_int("XInput", "ThrottleDeadzone", 8689);
    pad_stick_dz = ini_int("XInput", "StickDeadzone", 2500);
    axis_kbd_speed = ini_int("Keyboard", "AxisSpeed", 16);
}

static int key_down(int vk) { return vk && (GetAsyncKeyState(vk) & 0x8000); }

static SHORT deadzone(SHORT v, int dz) { return v > -dz && v < dz ? 0 : v; }

static BYTE stick_to_byte(SHORT v) { return (BYTE)((v + 32768) >> 8); }

static BYTE kbd_axis(BYTE cur, int neg, int pos)
{
    int v = cur;
    if (neg && !pos) v -= axis_kbd_speed;
    else if (pos && !neg) v += axis_kbd_speed;
    else { /* return to center */
        if (v > 0x80) v = v - axis_kbd_speed < 0x80 ? 0x80 : v - axis_kbd_speed;
        else if (v < 0x80) v = v + axis_kbd_speed > 0x80 ? 0x80 : v + axis_kbd_speed;
    }
    return (BYTE)(v < 0 ? 0 : v > 255 ? 255 : v);
}

static void input_poll(void)
{
    static BYTE kx = 0x80, ky = 0x80, kt = 0x80;
    XINSTATE st;
    int have_pad = 0, i, coin;
    memset(&st, 0, sizeof(st));
    if (real_XInputGetState && real_XInputGetState(pad_index, &st) == 0) have_pad = 1;

    for (i = 0; i < IN_COUNT; i++)
        io.dig[i] = key_down(in_key[i]) || (have_pad && in_pad[i] && (st.Gamepad.wButtons & in_pad[i]));

    kx = kbd_axis(kx, key_down(VK_LEFT), key_down(VK_RIGHT));
    ky = kbd_axis(ky, key_down(VK_UP), key_down(VK_DOWN));
    kt = kbd_axis(kt, key_down(VK_NEXT), key_down(VK_PRIOR));
    io.x = kx; io.y = ky; io.throttle = kt;

    if (have_pad) {
        XPAD *g = &st.Gamepad;
        /* left stick = joystick; stick down = same as the Up arrow key
         * (pitch up), like a flight stick */
        if (kx == 0x80) io.x = stick_to_byte(deadzone(g->sThumbLX, pad_stick_dz));
        if (ky == 0x80) io.y = stick_to_byte(deadzone(g->sThumbLY, pad_stick_dz));
        /* throttle: right stick up / RT accelerate, right stick down / LT brake */
        if (kt == 0x80) {
            int ry = deadzone(g->sThumbRY, pad_deadzone), t;
            t = 0x80 + (g->bRightTrigger - g->bLeftTrigger) / 2 + ry / 256;
            io.throttle = (BYTE)(t < 0 ? 0 : t > 255 ? 255 : t);
        }
        /* default pad buttons when not mapped in ini */
        if (!in_pad[IN_START]) io.dig[IN_START] |= !!(g->wButtons & 0x0010);
        if (!in_pad[IN_TRIGGER]) io.dig[IN_TRIGGER] |= !!(g->wButtons & 0x4200);     /* X or RB */
        if (!in_pad[IN_WEAPON]) io.dig[IN_WEAPON] |= !!(g->wButtons & 0x1100);       /* A or LB */
        if (!in_pad[IN_VIEW]) io.dig[IN_VIEW] |= !!(g->wButtons & 0x8000);           /* Y */
        if (!in_pad[IN_ENTER]) io.dig[IN_ENTER] |= !!(g->wButtons & 0x2000);         /* B */
        if (!in_pad[IN_MENU_UP]) io.dig[IN_MENU_UP] |= !!(g->wButtons & 0x0001);     /* dpad */
        if (!in_pad[IN_MENU_DOWN]) io.dig[IN_MENU_DOWN] |= !!(g->wButtons & 0x0002);
    }
    if (ini_int("General", "ReverseY", 0)) io.y = (BYTE)~io.y;
    if (ini_int("General", "ReverseThrottle", 0)) io.throttle = (BYTE)~io.throttle;

    /* the cabinet's test switch is a latching switch: the game stays in the
     * test menu only while it is on, so make the key toggle it */
    if (ini_int("General", "TestToggle", 1)) {
        static int test_prev, test_on;
        if (io.dig[IN_TEST] && !test_prev) test_on = !test_on;
        test_prev = io.dig[IN_TEST];
        io.dig[IN_TEST] = (BYTE)test_on;
    }
    /* in the test menu, the Up/Down arrows also move the menu cursor */
    if (io.dig[IN_TEST]) {
        io.dig[IN_MENU_UP] |= key_down(VK_UP) ? 1 : 0;
        io.dig[IN_MENU_DOWN] |= key_down(VK_DOWN) ? 1 : 0;
    }

    if (ini_int("Debug", "InputLog", 0)) {
        static char prev[64];
        char cur[64]; int o = 0, k;
        for (k = 0; k < IN_COUNT; k++) cur[o++] = io.dig[k] ? '1' : '0';
        o += wsprintfA(cur + o, " t%02x x%02x y%02x pad%d", io.throttle, io.x, io.y, have_pad);
        if (strcmp(cur, prev)) { logf("input %s", cur); memcpy(prev, cur, o + 1); }
    }

    coin = io.dig[IN_COIN];
    if (coin_prev && !coin) io.coins++;  /* count on release, like TeknoParrot */
    coin_prev = coin;
}

/* ------------------------------------------------------------------- JVS */

#define JVS_SYNC 0xE0
#define JVS_MARK 0xD0
static const char jvs_ident[] = "namco ltd.;NA-JV;Ver4.00;JPN,Multipurpose.";

static HANDLE jvs_handle;          /* fake COM handle (an event) */
static int jvs_addressed;
static BYTE jvs_in[1024]; static int jvs_in_len;   /* raw bytes written by the game */
static BYTE jvs_out[4096]; static int jvs_out_len, jvs_out_pos;
static CRITICAL_SECTION jvs_cs;
static int jvs_trace;

static void out_byte(BYTE b)
{
    if (jvs_out_len + 2 > (int)sizeof(jvs_out)) return;
    if (b == JVS_SYNC || b == JVS_MARK) { jvs_out[jvs_out_len++] = JVS_MARK; b--; }
    jvs_out[jvs_out_len++] = b;
}

static void jvs_reply(const BYTE *payload, int n)  /* payload = status-less report data */
{
    BYTE sum = 0, hdr[3] = { 0x00, (BYTE)(n + 2), 0x01 }; /* node 0 (master), len, status OK */
    int i;
    jvs_out[jvs_out_len++] = JVS_SYNC;
    for (i = 0; i < 3; i++) { out_byte(hdr[i]); sum += hdr[i]; }
    for (i = 0; i < n; i++) { out_byte(payload[i]); sum += payload[i]; }
    out_byte(sum);
}

static BYTE p1_sw0(void)
{
    BYTE r = 0;
    if (io.dig[IN_START]) r |= 0x80;
    if (io.dig[IN_SERVICE]) r |= 0x40;
    if (io.dig[IN_MENU_UP]) r |= 0x20;
    if (io.dig[IN_MENU_DOWN]) r |= 0x10;
    if (io.dig[IN_ENTER]) r |= 0x02;
    return r;
}
static BYTE p1_sw1(void) { return io.dig[IN_VIEW] ? 0x80 : 0; }
static BYTE p1_sw2(void) { return (io.dig[IN_WEAPON] ? 0x01 : 0) | (io.dig[IN_TRIGGER] ? 0x02 : 0); }

/* process one complete (unescaped) packet: node len cmd... sum */
static void jvs_packet(const BYTE *p, int n)
{
    BYTE rep[1024];
    int r = 0, i = 2, end = n - 1;  /* commands are p[2 .. n-2] */
    BYTE node = p[0];

    if (p[2] == 0xF0) { jvs_addressed = 0; return; }  /* reset: no reply */
    if (node != 0xFF && node != 0x01) return;           /* not for us */

    input_poll();
    while (i < end) {
        BYTE c = p[i];
        switch (c) {
        case 0xF1: /* set address */
            jvs_addressed = 1; rep[r++] = 1; i += 2; break;
        case 0x10: { /* identify */
            rep[r++] = 1;
            memcpy(rep + r, jvs_ident, sizeof(jvs_ident)); r += sizeof(jvs_ident); /* incl. NUL */
            i += 1; break; }
        case 0x11: rep[r++] = 1; rep[r++] = 0x31; i += 1; break; /* command rev */
        case 0x12: rep[r++] = 1; rep[r++] = 0x31; i += 1; break; /* JVS version */
        case 0x13: rep[r++] = 1; rep[r++] = 0x31; i += 1; break; /* comm version */
        case 0x14: { /* features */
            static const BYTE f[] = { 1, 0x01, 2, 0x18, 0,  0x02, 2, 0, 0,  0x03, 8, 0x0A, 0,
                                      0x12, 0x14, 0, 0,  0x00 };
            memcpy(rep + r, f, sizeof(f)); r += sizeof(f); i += 1; break; }
        case 0x15: /* main board id: string */
            rep[r++] = 1; i++;
            while (i < end && p[i]) i++;
            i++; break;
        case 0x20: { /* switches: players, bytes */
            int pl = p[i + 1], nb = p[i + 2], k, j;
            rep[r++] = 1;
            rep[r++] = io.dig[IN_TEST] ? 0x80 : 0;
            for (k = 0; k < pl; k++)
                for (j = 0; j < nb; j++)
                    rep[r++] = k ? 0 : j == 0 ? p1_sw0() : j == 1 ? p1_sw1() : j == 2 ? p1_sw2() : 0;
            i += 3; break; }
        case 0x21: { /* coins */
            int sl = p[i + 1], k;
            rep[r++] = 1;
            for (k = 0; k < sl; k++) {
                int c2 = k ? 0 : io.coins;
                rep[r++] = (BYTE)((c2 >> 8) & 0x3F); rep[r++] = (BYTE)c2;
            }
            i += 2; break; }
        case 0x22: { /* analogs */
            int ch = p[i + 1], k;
            rep[r++] = 1;
            for (k = 0; k < ch; k++) {
                BYTE v = k == 1 ? io.throttle : k == 2 ? io.x : k == 3 ? io.y : 0x80;
                rep[r++] = v; rep[r++] = 0;
            }
            i += 2; break; }
        case 0x26: { /* misc switches */
            int nb = p[i + 1], k;
            rep[r++] = 1;
            for (k = 0; k < nb; k++) rep[r++] = 0;
            i += 2; break; }
        case 0x2E: rep[r++] = 1; memset(rep + r, 0, 4); r += 4; i += 2; break; /* hopper */
        case 0x2F: rep[r++] = 1; i += 1; break; /* retransmit: unsupported, ack */
        case 0x30: case 0x31: { /* coin decrease / increase */
            int cnt = (p[i + 2] << 8) | p[i + 3];
            if (p[i + 1] == 1) io.coins += c == 0x30 ? -cnt : cnt;
            if (io.coins < 0) io.coins = 0;
            rep[r++] = 1; i += 4; break; }
        case 0x32: rep[r++] = 1; i += 2 + p[i + 1]; break;       /* GPO */
        case 0x33: rep[r++] = 1; i += 2 + 2 * p[i + 1]; break;   /* analog out */
        case 0x34: rep[r++] = 1; i += 2 + p[i + 1]; break;       /* char out */
        case 0x35: rep[r++] = 1; i += 4; break;                  /* coin add */
        case 0x36: rep[r++] = 1; i += 4; break;                  /* payout sub */
        case 0x37: rep[r++] = 1; i += 3; break;                  /* GPO byte */
        case 0x38: rep[r++] = 1; i += 3; break;                  /* GPO bit */
        case 0x70: { /* namco custom */
            BYTE sub = p[i + 1];
            if (sub == 0x18) { rep[r++] = 1; rep[r++] = 1; i = end; }
            else if (sub == 0x05) { rep[r++] = 1; rep[r++] = 1; i += p[i + 2] ? p[i + 2] : 1; }
            else if (sub == 0x03) { rep[r++] = 1; rep[r++] = 0; i += 4; }
            else if (sub == 0x15 || sub == 0x16) { rep[r++] = 1; rep[r++] = 1; i += 4; }
            else { logf("jvs: unknown namco 70 %02x", sub); rep[r++] = 1; i = end; }
            break; }
        case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F: case 0x80:
            rep[r++] = 1; i += 15; break;
        default:
            logf("jvs: unknown cmd %02x (packet len %d)", c, n);
            rep[r++] = 2; /* report: parameter error */
            i = end; break;
        }
    }
    if (jvs_trace) {
        char s[600]; int k, o = 0;
        for (k = 0; k < n && o < 560; k++) o += wsprintfA(s + o, "%02x", p[k]);
        logf("jvs <- %s", s);
    }
    jvs_reply(rep, r);
}

static void jvs_feed(const BYTE *buf, DWORD n)
{
    DWORD k;
    for (k = 0; k < n; k++) {
        BYTE b = buf[k];
        if (b == JVS_SYNC) { jvs_in_len = 0; jvs_in[jvs_in_len++] = b; continue; }
        if (!jvs_in_len) continue;
        if (jvs_in_len < (int)sizeof(jvs_in)) jvs_in[jvs_in_len++] = b;
        /* unescape + check completeness: E0 node len data... */
        {
            BYTE pk[1024]; int m = 0, j, esc = 0;
            for (j = 1; j < jvs_in_len; j++) {
                if (esc) { pk[m++] = jvs_in[j] + 1; esc = 0; }
                else if (jvs_in[j] == JVS_MARK) esc = 1;
                else pk[m++] = jvs_in[j];
            }
            if (m >= 2 && m == pk[1] + 2) {
                jvs_packet(pk, m);
                jvs_in_len = 0;
            }
        }
    }
}

static HANDLE (WINAPI *real_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static HANDLE (WINAPI *real_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static BOOL (WINAPI *real_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
static BOOL (WINAPI *real_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
static BOOL (WINAPI *real_CloseHandle)(HANDLE);
static BOOL (WINAPI *real_GetCommModemStatus)(HANDLE, LPDWORD);
static BOOL (WINAPI *real_GetCommState)(HANDLE, LPDCB);
static BOOL (WINAPI *real_SetCommState)(HANDLE, LPDCB);
static BOOL (WINAPI *real_SetCommTimeouts)(HANDLE, LPCOMMTIMEOUTS);
static BOOL (WINAPI *real_PurgeComm)(HANDLE, DWORD);
static BOOL (WINAPI *real_ClearCommError)(HANDLE, LPDWORD, LPCOMSTAT);

static char jvs_port[16] = "COM3";

/* name is "COMn" or "\\.\COMn" (ANSI, converted from W by the caller) */
static int is_jvs_port(const char *name)
{
    if (!strncmp(name, "\\\\.\\", 4)) name += 4;
    return !lstrcmpiA(name, jvs_port);
}

static HANDLE jvs_open(const char *name)
{
    logf("JVS port %s opened (emulated)", name);
    if (!jvs_handle) jvs_handle = CreateEventW(NULL, TRUE, TRUE, NULL);
    EnterCriticalSection(&jvs_cs);
    jvs_addressed = 0; jvs_in_len = jvs_out_len = jvs_out_pos = 0;
    LeaveCriticalSection(&jvs_cs);
    return jvs_handle;
}

static HANDLE WINAPI h_CreateFileA(LPCSTR name, DWORD acc, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                   DWORD disp, DWORD flags, HANDLE tmpl)
{
    if (name && is_jvs_port(name)) return jvs_open(name);
    if (name && (!strncmp(name, "COM", 3) || !strncmp(name, "\\\\.\\", 4))) logf("CreateFileA %s", name);
    return real_CreateFileA(name, acc, share, sa, disp, flags, tmpl);
}

static HANDLE WINAPI h_CreateFileW(LPCWSTR name, DWORD acc, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                   DWORD disp, DWORD flags, HANDLE tmpl)
{
    char a[MAX_PATH] = "";
    if (name) WideCharToMultiByte(CP_ACP, 0, name, -1, a, sizeof(a), NULL, NULL);
    if (name && is_jvs_port(a)) return jvs_open(a);
    if (name && (!strncmp(a, "COM", 3) || !strncmp(a, "\\\\.\\", 4))) logf("CreateFileW %s", a);
    return real_CreateFileW(name, acc, share, sa, disp, flags, tmpl);
}

static int jvs_pending(void) { return jvs_out_len - jvs_out_pos; }

static BOOL WINAPI h_ReadFile(HANDLE h, LPVOID buf, DWORD n, LPDWORD rd, LPOVERLAPPED ov)
{
    DWORD k = 0;
    if (h != jvs_handle || !h) return real_ReadFile(h, buf, n, rd, ov);
    EnterCriticalSection(&jvs_cs);
    while (k < n && jvs_out_pos < jvs_out_len) ((BYTE *)buf)[k++] = jvs_out[jvs_out_pos++];
    if (jvs_out_pos >= jvs_out_len) jvs_out_pos = jvs_out_len = 0;
    LeaveCriticalSection(&jvs_cs);
    if (!k) Sleep(1);
    if (rd) *rd = k;
    return TRUE;
}

static BOOL WINAPI h_WriteFile(HANDLE h, LPCVOID buf, DWORD n, LPDWORD wr, LPOVERLAPPED ov)
{
    if (h != jvs_handle || !h) return real_WriteFile(h, buf, n, wr, ov);
    EnterCriticalSection(&jvs_cs);
    jvs_feed(buf, n);
    LeaveCriticalSection(&jvs_cs);
    if (wr) *wr = n;
    return TRUE;
}

static BOOL WINAPI h_CloseHandle(HANDLE h)
{
    if (h && h == jvs_handle) { logf("JVS port closed"); return TRUE; }
    return real_CloseHandle(h);
}

static BOOL WINAPI h_GetCommModemStatus(HANDLE h, LPDWORD st)
{
    if (h != jvs_handle || !h) return real_GetCommModemStatus(h, st);
    *st = jvs_addressed ? 0x30 : 0x10;  /* same as OpenParrot: sense line */
    return TRUE;
}
static BOOL WINAPI h_GetCommState(HANDLE h, LPDCB d)
{
    if (h != jvs_handle || !h) return real_GetCommState(h, d);
    memset(d, 0, sizeof(*d)); d->DCBlength = sizeof(*d); d->BaudRate = 115200; d->ByteSize = 8;
    return TRUE;
}
static BOOL WINAPI h_SetCommState(HANDLE h, LPDCB d)
{ return (h == jvs_handle && h) ? TRUE : real_SetCommState(h, d); }
static BOOL WINAPI h_SetCommTimeouts(HANDLE h, LPCOMMTIMEOUTS t)
{ return (h == jvs_handle && h) ? TRUE : real_SetCommTimeouts(h, t); }
static BOOL WINAPI h_PurgeComm(HANDLE h, DWORD f)
{
    if (h != jvs_handle || !h) return real_PurgeComm(h, f);
    EnterCriticalSection(&jvs_cs);
    if (f & PURGE_RXCLEAR) jvs_out_len = jvs_out_pos = 0;
    if (f & PURGE_TXCLEAR) jvs_in_len = 0;
    LeaveCriticalSection(&jvs_cs);
    return TRUE;
}
static BOOL WINAPI h_ClearCommError(HANDLE h, LPDWORD err, LPCOMSTAT st)
{
    if (h != jvs_handle || !h) return real_ClearCommError(h, err, st);
    if (err) *err = 0;
    if (st) {
        memset(st, 0, sizeof(*st));
        EnterCriticalSection(&jvs_cs);
        st->cbInQue = jvs_pending();
        LeaveCriticalSection(&jvs_cs);
    }
    return TRUE;
}

/* emulate the JVS board on the serial port used by module m (kernel32 IAT) */
static void jvs_install(HMODULE m, const char *what)
{
    static int once;
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (!m) { logf("%s not loaded, JVS emulation disabled", what); return; }
    if (!once) {
        once = 1;
        InitializeCriticalSection(&jvs_cs);
        jvs_trace = ini_int("Debug", "JvsTrace", 0);
        GetPrivateProfileStringA("General", "JvsPort", "COM3", jvs_port, sizeof(jvs_port), g_ini);
    }
#define H(name) do { void *o = iat_hook(m, "KERNEL32.dll", #name, h_##name); \
        if (!real_##name) real_##name = o ? o : (void *)GetProcAddress(k32, #name); } while (0)
    H(CreateFileA); H(CreateFileW); H(ReadFile); H(WriteFile); H(CloseHandle); H(GetCommModemStatus);
    H(GetCommState); H(SetCommState); H(SetCommTimeouts); H(PurgeComm); H(ClearCommError);
#undef H
    logf("JVS emulation installed on %s (port %s)", what, jvs_port);
}

/* ----------------------------------------------------------------- XInput */

/* the game also reads XInput directly; give it neutral pads so the dev
 * controls do not interfere with the JVS ones (OpenParrot does the same) */
static DWORD WINAPI h_XInputGetState(DWORD idx, XINSTATE *s)
{
    if (s) memset(s, 0, sizeof(*s));
    return 0;
}
static DWORD WINAPI h_XInputSetState(DWORD idx, void *vib) { return 0; }

/* it also enumerates DirectInput game controllers (pad buttons would act
 * on their own, e.g. R1 = view): drop everything but keyboard and mouse */
typedef BOOL (CALLBACK *DIENUMCB)(const void *ddi, void *ref);
typedef HRESULT (WINAPI *EnumDevices_t)(void *self, DWORD type, DIENUMCB cb, void *ref, DWORD flags);
typedef HRESULT (WINAPI *DirectInput8Create_t)(HINSTANCE, DWORD, const GUID *, void **, void *);
static DirectInput8Create_t real_DirectInput8Create;
static struct { void **vt; EnumDevices_t real; } di_vt[4];  /* A and W interfaces */
struct di_enum { DIENUMCB cb; void *ref; };

static BOOL CALLBACK di_enum_filter(const void *ddi, void *ref)
{
    struct di_enum *e = ref;
    BYTE type = (BYTE)*(const DWORD *)((const BYTE *)ddi + 36);  /* DIDEVICEINSTANCE.dwDevType */
    if (type != 0x12 && type != 0x13) return TRUE;               /* DI8DEVTYPE_MOUSE/KEYBOARD */
    return e->cb(ddi, e->ref);
}
static HRESULT WINAPI h_EnumDevices(void *self, DWORD type, DIENUMCB cb, void *ref, DWORD flags)
{
    struct di_enum e = { cb, ref };
    int i;
    for (i = 0; i < 4; i++)
        if (di_vt[i].vt == *(void ***)self) return di_vt[i].real(self, type, di_enum_filter, &e, flags);
    return E_FAIL;
}
static HRESULT WINAPI h_DirectInput8Create(HINSTANCE h, DWORD ver, const GUID *riid, void **out, void *outer)
{
    HRESULT r = real_DirectInput8Create(h, ver, riid, out, outer);
    if (r == 0 && out && *out) {
        void **vt = *(void ***)*out, *fn = h_EnumDevices;
        int i;
        for (i = 0; i < 4 && vt[4] != fn; i++)
            if (!di_vt[i].vt) {  /* EnumDevices is slot 4 in both A and W vtables */
                di_vt[i].vt = vt;
                di_vt[i].real = vt[4];
                mem_write(&vt[4], &fn, sizeof(fn));
                logf("DirectInput game controllers hidden from the game");
            }
    }
    return r;
}

/* ---------------------------------------------------------------- patches */

static void patches_launcher(BYTE *base)
{
    /* projector monitor thread (started at 0x3bf12): opens COM1 and raises
     * error 0x31 "23-08 PROJECTOR OTHER ERROR" when absent -> exit at once */
    patch("projector thread", base, 0x3e4d0, "\x40\x53\x55\x56", "\x31\xC0\xC3\x90", 4);

    /* game mode argument: cabinet type/6 == 1 -> "-FLATSCREEN", 2 -> "-PREMIUM",
     * else dome (concave projection warp). Force the flat-screen render. */
    if (ini_int("General", "FlatScreen", 1))
        patch("flatscreen", base, 0x32475, "\x75\x09", "\x90\x90", 2);

    /* game language argument: [0x33cb60] = operator setting varSettingLanguage,
     * 1..8 -> "-Language=JPN/CHN/ITA/SPA/RUS/POR/IND/THA", else none (INT =
     * English). Replace that read with "mov eax, lang" unless Language=Setting. */
    {
        static const char *langs[] = { "ENG", "JPN", "CHN", "ITA", "SPA", "RUS", "POR", "IND", "THA" };
        char lang[16];
        int i;
        GetPrivateProfileStringA("General", "Language", "Setting", lang, sizeof(lang), g_ini);
        if (!lstrcmpiA(lang, "INT")) lstrcpyA(lang, "ENG");
        for (i = 0; i < 9; i++)
            if (!lstrcmpiA(lang, langs[i])) {
                BYTE mov[6] = { 0xB8, (BYTE)i, 0, 0, 0, 0x90 };
                patch("language", base, 0x324ef, "\x8b\x05\x6b\xa6\x30\x00", mov, 6);
                logf("game language forced to %s", langs[i]);
            }
    }
}

/* "USB DONGLE" = a USB key (not the HASP) found by enumerating USB devices
 * through SetupDi (game 0x20b0). The caller (0x9dc110) wants exactly one
 * device, word +0x22 == 0x0c10 and a 12-wchar serial at +0x428 matching
 * the live serial template (decrypted at runtime; [0x150d810] picks which). Otherwise:
 * 0 devices -> 19-22, >1 -> 0x37, wrong id/serial -> 19-21. */

static int __cdecl h_usb_key_enum(int a, int b, unsigned short c, unsigned short d, BYTE *out)
{
    /* the serial template is decrypted at runtime (file: "******22****",
     * live: "27431022****"), so build the serial from the live one. With
     * [0x2022254] != 1 and [0x150d810] == 0 (no -Language=JPN) the caller
     * first checks the HASP, then wants the "TFA KEY": id 0x0c20, template
     * 0x1573d48 (else error 0x39 = 20-01) */
    int tfa = *(DWORD *)(g_game_base + 0x2022254) != 1 && !*(DWORD *)(g_game_base + 0x150d810);
    const char *tmpl = (const char *)g_game_base + (tfa ? 0x1573d48 :
        *(DWORD *)(g_game_base + 0x150d810) ? 0x12b4c98 : 0x1573d28);
    static int logged;
    char serial[13];
    int i;
    for (i = 0; i < 12; i++) serial[i] = (tmpl[i] == '*' || !tmpl[i]) ? '0' : tmpl[i];
    serial[12] = 0;
    memset(out, 0, 0x628);
    *(WORD *)(out + 0x22) = tfa ? 0x0c20 : 0x0c10;
    for (i = 0; i < 12; i++) ((WCHAR *)(out + 0x428))[i] = serial[i];
    if (!logged++) logf("USB key enumeration -> 1 device%s, serial %s (polled every 3 s)", tfa ? " (TFA key)" : "", serial);
    return 1;
}

static void detour(const char *what, BYTE *at, const void *expect, void *fn)
{
    BYTE j[12] = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };  /* mov rax, fn; jmp rax */
    memcpy(j + 2, &fn, 8);
    patch(what, at, 0, expect, j, sizeof(j));
}

static void patches_game(BYTE *base)
{
    g_game_base = base;
    detour("usb key enum", base + 0x20b0, "\x40\x55\x57\x41\x55\x41\x56\x41\x57\x48\x8d\xac", h_usb_key_enum);
}

/* ------------------------------------------------------------------- init */

static void init(void)
{
    char exe[MAX_PATH], *p, *slash;
    GetModuleFileNameA(NULL, exe, sizeof(exe));
    slash = strrchr(exe, '\\');
    p = slash ? slash + 1 : exe;
    g_is_launcher = !lstrcmpiA(p, "RSLauncher.exe");
    g_is_game = !lstrcmpiA(p, "SWArcGame-Win64-Shipping.exe");

    /* root = exe dir minus "Launcher" or "Binaries\Win64" */
    lstrcpynA(g_root, exe, sizeof(g_root));
    if ((slash = strrchr(g_root, '\\'))) *slash = 0;
    if (g_is_game) {
        if ((slash = strrchr(g_root, '\\'))) *slash = 0;
        if ((slash = strrchr(g_root, '\\'))) *slash = 0;
    } else if (g_is_launcher) {
        if ((slash = strrchr(g_root, '\\'))) *slash = 0;
    }
    wsprintfA(g_ini, "%s\\swpod.ini", g_root);
    if (ini_int("Debug", "Log", 1)) {
        char lp[MAX_PATH];
        wsprintfA(lp, "%s\\swpod.log", g_root);
        g_log = CreateFileA(lp, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    logf("swpod loaded in %s (cmdline: %s)", exe, GetCommandLineA());
    hasp_init();

    if (g_is_launcher) {
        input_config();
        real_XInputGetState = (XInputGetState_t)GetProcAddress(LoadLibraryA("xinput1_3.dll"), "XInputGetState");
        jvs_install(GetModuleHandleA(NULL), "RSLauncher.exe");
        patches_launcher((BYTE *)GetModuleHandleA(NULL));
    } else if (g_is_game) {
        HMODULE xi = LoadLibraryA("xinput1_3.dll");
        input_config();
        real_XInputGetState = (XInputGetState_t)GetProcAddress(xi, "XInputGetState");
        /* the game uses wajvio.dll (WAJVOpen("COM3")); wajvio_com.dll is the
         * same library with WAJVCom* names - hook both */
        jvs_install(GetModuleHandleA("wajvio.dll"), "wajvio.dll");
        jvs_install(GetModuleHandleA("wajvio_com.dll"), "wajvio_com.dll");
        if (ini_int("General", "BlockGameXInput", 1)) {
            iat_hook_ex(NULL, "XINPUT1_3.dll", NULL, 2, h_XInputGetState);
            iat_hook_ex(NULL, "XINPUT1_3.dll", NULL, 3, h_XInputSetState);
            real_DirectInput8Create = iat_hook(NULL, "DINPUT8.dll", "DirectInput8Create", h_DirectInput8Create);
        }
        patches_game((BYTE *)GetModuleHandleA(NULL));
    }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = h;
        DisableThreadLibraryCalls(h);
        init();
    }
    return TRUE;
}
