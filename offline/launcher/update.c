/* SHODAN Stat Editor Offline: installs a downloaded update (update.lua asks for it; the download is fetch.c's).
   shodan_install(zip, program, dir, exe, exe_size, msg, msg_size): reads the release zip (this program's files in
   one folder), unpacks every file in memory and checks it (CRC-32), then swaps them in over `program`: each old
   file is renamed to *.old (a running exe or a loaded DLL can be renamed, not overwritten) and the new one written
   in its place; on any failure everything is put back. The *.old files are listed in <dir>\set aside.txt, for
   shodan_cleanup at the next start. 1: done (exe: the new program; msg: the files written, one per line);
   0: not done (msg: why, in English).
   shodan_launch(exe): starts the updated program in its folder.
   shodan_cleanup(dir): removes what an update set aside (what is still in use stays listed for the next start)
   and the update folder's other leftovers; 1 when the folder is gone. */
#include <windows.h>
#include <string.h>
#include <stdlib.h>

/* ---------------------------------------------------------------- inflate (raw deflate, RFC 1951) */
typedef struct {
    const unsigned char *in; size_t inlen, inpos;
    unsigned bitbuf, bitcnt;
    unsigned char *out; size_t outlen, outpos;
    int err;
} inflate_state;

typedef struct { short count[16], symbol[288]; } huffman;

static unsigned bits(inflate_state *s, unsigned need) {
    unsigned long val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->inpos >= s->inlen) { s->err = 1; return 0; }
        val |= (unsigned long)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = (unsigned)(val >> need);
    s->bitcnt -= need;
    return (unsigned)(val & ((1UL << need) - 1));
}

static int stored(inflate_state *s) {
    unsigned len;
    s->bitbuf = 0; s->bitcnt = 0;   /* to the byte boundary */
    if (s->inpos + 4 > s->inlen) return 1;
    len = s->in[s->inpos] | (s->in[s->inpos + 1] << 8);
    if ((s->in[s->inpos + 2] | (s->in[s->inpos + 3] << 8)) != (~len & 0xffff)) return 1;
    s->inpos += 4;
    if (s->inpos + len > s->inlen || s->outpos + len > s->outlen) return 1;
    memcpy(s->out + s->outpos, s->in + s->inpos, len);
    s->inpos += len; s->outpos += len;
    return 0;
}

static int decode(inflate_state *s, const huffman *h) {
    int code = 0, first = 0, index = 0, len, count;
    for (len = 1; len <= 15; len++) {
        code |= (int)bits(s, 1);
        if (s->err) return -1;
        count = h->count[len];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count; first += count;
        first <<= 1; code <<= 1;
    }
    return -1;
}

/* 0: a complete or incomplete code; 1: over-subscribed (invalid) */
static int construct(huffman *h, const short *length, int n) {
    short offs[16];
    int symbol, len, left = 1;
    for (len = 0; len <= 15; len++) h->count[len] = 0;
    for (symbol = 0; symbol < n; symbol++) h->count[length[symbol]]++;
    if (h->count[0] == n) return 0;
    for (len = 1; len <= 15; len++) {
        left <<= 1; left -= h->count[len];
        if (left < 0) return 1;
    }
    offs[1] = 0;
    for (len = 1; len < 15; len++) offs[len + 1] = offs[len] + h->count[len];
    for (symbol = 0; symbol < n; symbol++)
        if (length[symbol] != 0) h->symbol[offs[length[symbol]]++] = (short)symbol;
    return 0;
}

static int codes(inflate_state *s, const huffman *lencode, const huffman *distcode) {
    static const short lbase[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83,
                                     99, 115, 131, 163, 195, 227, 258 };
    static const short lext[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
    static const short dbase[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
                                     1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
    static const short dext[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
                                    12, 12, 13, 13 };
    int symbol;
    size_t len, dist;
    for (;;) {
        symbol = decode(s, lencode);
        if (symbol < 0) return 1;
        if (symbol < 256) {
            if (s->outpos >= s->outlen) return 1;
            s->out[s->outpos++] = (unsigned char)symbol;
        } else if (symbol == 256) {
            return 0;
        } else {
            symbol -= 257;
            if (symbol >= 29) return 1;
            len = lbase[symbol] + bits(s, lext[symbol]);
            symbol = decode(s, distcode);
            if (symbol < 0 || symbol >= 30) return 1;
            dist = dbase[symbol] + bits(s, dext[symbol]);
            if (s->err || dist > s->outpos || s->outpos + len > s->outlen) return 1;
            while (len--) { s->out[s->outpos] = s->out[s->outpos - dist]; s->outpos++; }
        }
    }
}

static int fixed(inflate_state *s) {
    static huffman lencode, distcode;
    static int built = 0;
    if (!built) {
        short lengths[288];
        int symbol;
        for (symbol = 0; symbol < 144; symbol++) lengths[symbol] = 8;
        for (; symbol < 256; symbol++) lengths[symbol] = 9;
        for (; symbol < 280; symbol++) lengths[symbol] = 7;
        for (; symbol < 288; symbol++) lengths[symbol] = 8;
        construct(&lencode, lengths, 288);
        for (symbol = 0; symbol < 30; symbol++) lengths[symbol] = 5;
        construct(&distcode, lengths, 30);
        built = 1;
    }
    return codes(s, &lencode, &distcode);
}

static int dynamic(inflate_state *s) {
    static const short order[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    short lengths[320];
    huffman lencode, distcode;
    int nlen, ndist, ncode, index, symbol, len;
    nlen = (int)bits(s, 5) + 257; ndist = (int)bits(s, 5) + 1; ncode = (int)bits(s, 4) + 4;
    if (s->err || nlen > 286 || ndist > 30) return 1;
    for (index = 0; index < ncode; index++) lengths[order[index]] = (short)bits(s, 3);
    for (; index < 19; index++) lengths[order[index]] = 0;
    if (s->err || construct(&lencode, lengths, 19)) return 1;
    index = 0;
    while (index < nlen + ndist) {
        symbol = decode(s, &lencode);
        if (symbol < 0) return 1;
        if (symbol < 16) {
            lengths[index++] = (short)symbol;
        } else {
            len = 0;
            if (symbol == 16) {
                if (index == 0) return 1;
                len = lengths[index - 1];
                symbol = 3 + (int)bits(s, 2);
            } else if (symbol == 17) {
                symbol = 3 + (int)bits(s, 3);
            } else {
                symbol = 11 + (int)bits(s, 7);
            }
            if (s->err || index + symbol > nlen + ndist) return 1;
            while (symbol--) lengths[index++] = (short)len;
        }
    }
    if (lengths[256] == 0) return 1;
    if (construct(&lencode, lengths, nlen) || construct(&distcode, lengths + nlen, ndist)) return 1;
    return codes(s, &lencode, &distcode);
}

/* 0: `in` unpacked into exactly `outlen` bytes */
static int inflate_raw(const unsigned char *in, size_t inlen, unsigned char *out, size_t outlen) {
    inflate_state s;
    unsigned last, type;
    int bad;
    memset(&s, 0, sizeof(s));
    s.in = in; s.inlen = inlen; s.out = out; s.outlen = outlen;
    do {
        last = bits(&s, 1);
        type = bits(&s, 2);
        if (s.err) return 1;
        bad = type == 0 ? stored(&s) : type == 1 ? fixed(&s) : type == 2 ? dynamic(&s) : 1;
        if (bad || s.err) return 1;
    } while (!last);
    return s.outpos != outlen;
}

static unsigned long crc32_of(const unsigned char *p, size_t n) {
    static unsigned long table[256];
    static int built = 0;
    unsigned long c = 0xffffffffUL;
    size_t k;
    if (!built) {
        unsigned long v;
        int i, j;
        for (i = 0; i < 256; i++) {
            v = (unsigned long)i;
            for (j = 0; j < 8; j++) v = (v & 1) ? 0xedb88320UL ^ (v >> 1) : v >> 1;
            table[i] = v;
        }
        built = 1;
    }
    for (k = 0; k < n; k++) c = table[(c ^ p[k]) & 0xff] ^ (c >> 8);
    return c ^ 0xffffffffUL;
}

/* ---------------------------------------------------------------- files */
static void say(char *msg, int size, const char *text) {
    if (size > 0) { lstrcpynA(msg, text, size); }
}

static void slashes(wchar_t *p) { for (; *p; p++) if (*p == L'/') *p = L'\\'; }

static int exists(const wchar_t *path) { return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES; }

/* the folders on the way to a file (path: a file's full path) */
static void parents(const wchar_t *path) {
    wchar_t part[1024];
    int k, n = lstrlenW(path);
    if (n >= 1024) return;
    for (k = 0; k < n; k++) {
        if (path[k] == L'\\' && k > 0 && path[k - 1] != L':') {
            memcpy(part, path, k * sizeof(wchar_t)); part[k] = 0;
            CreateDirectoryW(part, NULL);
        }
    }
}

static int write_all(const wchar_t *path, const unsigned char *data, size_t size) {
    HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD wrote = 0;
    int ok;
    if (f == INVALID_HANDLE_VALUE) return 0;
    ok = size == 0 || (WriteFile(f, data, (DWORD)size, &wrote, NULL) && wrote == size);
    CloseHandle(f);
    if (!ok) DeleteFileW(path);
    return ok;
}

static unsigned char *read_all(const wchar_t *path, size_t *size) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    LARGE_INTEGER n;
    unsigned char *data = NULL;
    DWORD got = 0;
    if (f == INVALID_HANDLE_VALUE) return NULL;
    if (GetFileSizeEx(f, &n) && n.QuadPart > 0 && n.QuadPart < 512 * 1024 * 1024) {
        data = (unsigned char *)malloc((size_t)n.QuadPart);
        if (data && !(ReadFile(f, data, (DWORD)n.QuadPart, &got, NULL) && got == (DWORD)n.QuadPart)) { free(data); data = NULL; }
        if (data) *size = (size_t)n.QuadPart;
    }
    CloseHandle(f);
    return data;
}

static void remove_tree(const wchar_t *folder) {
    wchar_t pattern[1024], path[1024];
    WIN32_FIND_DATAW e;
    HANDLE find;
    if (lstrlenW(folder) > 1000) return;
    wsprintfW(pattern, L"%s\\*", folder);
    find = FindFirstFileW(pattern, &e);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (!lstrcmpW(e.cFileName, L".") || !lstrcmpW(e.cFileName, L"..")) continue;
            wsprintfW(path, L"%s\\%s", folder, e.cFileName);
            if (e.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) remove_tree(path); else DeleteFileW(path);
        } while (FindNextFileW(find, &e));
        FindClose(find);
    }
    RemoveDirectoryW(folder);
}

/* ---------------------------------------------------------------- the zip */
typedef struct {
    wchar_t rel[512];        /* its path inside the program's folder, with backslashes */
    unsigned char *data;
    size_t size;
} entry;

static unsigned u16(const unsigned char *p) { return p[0] | (p[1] << 8); }
static unsigned long u32(const unsigned char *p) {
    return (unsigned long)p[0] | ((unsigned long)p[1] << 8) | ((unsigned long)p[2] << 16) | ((unsigned long)p[3] << 24);
}

static void free_entries(entry *list, int n) {
    int k;
    for (k = 0; k < n; k++) free(list[k].data);
    free(list);
}

/* every file of the zip, unpacked and checked, as paths below its one top folder; NULL and why if not */
static entry *unpack(const unsigned char *zip, size_t size, int *count, const char **why) {
    size_t end = 0, at, k;
    unsigned long total, cd;
    entry *list;
    int n = 0, i, top_len = -1;
    char top[256];
    *why = "the download is not a release of this program";
    if (size < 22) return NULL;
    for (k = size - 22; ; k--) {   /* the end of the central directory (a comment may follow it) */
        if (u32(zip + k) == 0x06054b50UL) { end = k; break; }
        if (k == 0 || size - k > 65536 + 22) return NULL;
    }
    total = u16(zip + end + 10);
    cd = u32(zip + end + 16);
    if (total == 0 || total > 4096 || cd >= size) return NULL;
    list = (entry *)calloc(total, sizeof(entry));
    if (!list) return NULL;
    at = cd;
    for (i = 0; i < (int)total; i++) {
        unsigned method, flags, name_len, extra_len, comment_len, local_name, local_extra;
        unsigned long crc, packed, plain, local;
        char name[512];
        const unsigned char *src;
        size_t data_at;
        int len, j;
        if (at + 46 > size || u32(zip + at) != 0x02014b50UL) goto bad;
        flags = u16(zip + at + 8); method = u16(zip + at + 10);
        crc = u32(zip + at + 16); packed = u32(zip + at + 20); plain = u32(zip + at + 24);
        name_len = u16(zip + at + 28); extra_len = u16(zip + at + 30); comment_len = u16(zip + at + 32);
        local = u32(zip + at + 42);
        if (name_len == 0 || name_len >= sizeof(name) || at + 46 + name_len > size) goto bad;
        memcpy(name, zip + at + 46, name_len); name[name_len] = 0;
        at += 46 + name_len + extra_len + comment_len;
        if (flags & 1) goto bad;                                   /* encrypted */
        /* no absolute paths, drive letters, backslashes or '..' parts */
        if (name[0] == '/' || strchr(name, '\\') || strchr(name, ':')) goto bad;
        for (j = 0; name[j]; j++)
            if (name[j] == '.' && name[j + 1] == '.' && (j == 0 || name[j - 1] == '/') && (name[j + 2] == '/' || !name[j + 2])) goto bad;
        /* one top folder holds everything */
        {
            const char *slash = strchr(name, '/');
            if (!slash) goto bad;
            len = (int)(slash - name);
            if (top_len < 0) {
                if (len >= (int)sizeof(top)) goto bad;
                memcpy(top, name, len); top[len] = 0; top_len = len;
            } else if (len != top_len || memcmp(top, name, len) != 0) {
                goto bad;
            }
        }
        if (name[name_len - 1] == '/') continue;                   /* a folder */
        if (name_len <= (unsigned)top_len + 1) goto bad;
        if (method != 0 && method != 8) { *why = "the download is packed in a way this program can't unpack"; goto fail; }
        if (packed == 0xffffffffUL || plain == 0xffffffffUL || plain > 256 * 1024 * 1024) goto bad;
        if (local + 30 > size || u32(zip + local) != 0x04034b50UL) goto bad;
        local_name = u16(zip + local + 26); local_extra = u16(zip + local + 28);
        data_at = local + 30 + local_name + local_extra;
        if (data_at + packed > size) goto bad;
        src = zip + data_at;
        list[n].size = plain;
        list[n].data = (unsigned char *)malloc(plain ? plain : 1);
        if (!list[n].data) { *why = "not enough memory to unpack the download"; goto fail; }
        if (method == 0 ? (packed != plain || (memcpy(list[n].data, src, plain), 0))
                        : inflate_raw(src, packed, list[n].data, plain)) {
            *why = "the download is damaged (it could not be unpacked)"; n++; goto fail;
        }
        if (crc32_of(list[n].data, plain) != crc) { *why = "the download is damaged (a file's checksum is wrong)"; n++; goto fail; }
        if (!MultiByteToWideChar(CP_UTF8, 0, name + top_len + 1, -1, list[n].rel, 512)) { n++; goto bad; }
        slashes(list[n].rel);
        n++;
    }
    if (n == 0) goto bad;
    *count = n;
    return list;
bad:
    *why = "the download is not a release of this program";
fail:
    free_entries(list, n);
    return NULL;
}

/* ---------------------------------------------------------------- installing */
typedef struct { wchar_t target[1024]; int old; } swapped;

static void undo(swapped *done, int n) {
    wchar_t old[1100];
    int k;
    for (k = n - 1; k >= 0; k--) {
        DeleteFileW(done[k].target);
        if (done[k].old) {
            wsprintfW(old, L"%s.old", done[k].target);
            MoveFileExW(old, done[k].target, MOVEFILE_REPLACE_EXISTING);
        }
    }
}

static void append_utf8(char *msg, int size, const wchar_t *text, const char *before) {
    int used = lstrlenA(msg), room = size - used;
    if (room <= 1) return;
    lstrcpynA(msg + used, before, room);
    used = lstrlenA(msg); room = size - used;
    if (room <= 1) return;
    if (!WideCharToMultiByte(CP_UTF8, 0, text, -1, msg + used, room, NULL, NULL)) msg[used] = 0;
}

__declspec(dllexport) int shodan_install(const wchar_t *zip_path, const wchar_t *program_in, const wchar_t *dir_in,
                                         wchar_t *exe_out, int exe_size, char *msg, int msg_size) {
    wchar_t program[1024], dir[1024], running[1024], list_path[1100], old[1100];
    unsigned char *zip;
    size_t zip_size = 0;
    entry *files;
    swapped *done;
    int count = 0, k, n = 0, exe = -1, host = 0, panel = 0, plen;
    const char *why = NULL;
    char *aside;
    HANDLE f;

    if (msg_size > 0) msg[0] = 0;
    if (exe_size > 0) exe_out[0] = 0;
    if (lstrlenW(program_in) >= 1000 || lstrlenW(dir_in) >= 1000) { say(msg, msg_size, "the program's folder path is too long"); return 0; }
    lstrcpyW(program, program_in); slashes(program);
    plen = lstrlenW(program);
    while (plen > 0 && program[plen - 1] == L'\\') program[--plen] = 0;
    lstrcpyW(dir, dir_in); slashes(dir);

    zip = read_all(zip_path, &zip_size);
    if (!zip) { say(msg, msg_size, "the download could not be read"); return 0; }
    files = unpack(zip, zip_size, &count, &why);
    free(zip);
    if (!files) { say(msg, msg_size, why); return 0; }

    /* a release: one program at the top, the host and the editor in app\ */
    for (k = 0; k < count; k++) {
        int len = lstrlenW(files[k].rel);
        if (!wcschr(files[k].rel, L'\\') && len > 4 && !lstrcmpiW(files[k].rel + len - 4, L".exe")) {
            if (exe >= 0) { free_entries(files, count); say(msg, msg_size, "the download holds two programs"); return 0; }
            exe = k;
        }
        if (!lstrcmpiW(files[k].rel, L"app\\host.lua")) host = 1;
        if (!lstrcmpiW(files[k].rel, L"app\\stat_editor.lua")) panel = 1;
        if (plen + 1 + len >= 1000) { free_entries(files, count); say(msg, msg_size, "the program's folder path is too long"); return 0; }
    }
    if (exe < 0 || !host || !panel) { free_entries(files, count); say(msg, msg_size, "the download is not a release of this program"); return 0; }

    /* swap: each file in place, the old one kept as *.old */
    done = (swapped *)calloc(count, sizeof(swapped));
    if (!done) { free_entries(files, count); say(msg, msg_size, "not enough memory to install the update"); return 0; }
    for (k = 0; k < count; k++) {
        wchar_t *target = done[n].target;
        int had;
        wsprintfW(target, L"%s\\%s", program, files[k].rel);
        parents(target);
        had = exists(target);
        wsprintfW(old, L"%s.old", target);
        if (had && !MoveFileExW(target, old, MOVEFILE_REPLACE_EXISTING)) {
            undo(done, n);
            say(msg, msg_size, "could not replace ");
            append_utf8(msg, msg_size, files[k].rel, "");
            append_utf8(msg, msg_size, L" (is it open somewhere?)", "");
            free(done); free_entries(files, count);
            return 0;
        }
        if (!write_all(target, files[k].data, files[k].size)) {
            if (had) MoveFileExW(old, target, MOVEFILE_REPLACE_EXISTING);
            undo(done, n);
            say(msg, msg_size, "could not write ");
            append_utf8(msg, msg_size, files[k].rel, "");
            free(done); free_entries(files, count);
            return 0;
        }
        done[n].old = had;
        n++;
    }
    for (k = 0; k < count; k++) append_utf8(msg, msg_size, files[k].rel, k ? "\n" : "");

    /* the *.old files, for shodan_cleanup at the next start (one UTF-8 path per line) */
    aside = (char *)calloc((size_t)(n + 1) * 3300, 1);
    if (aside) {
        for (k = 0; k < n; k++)
            if (done[k].old) { wsprintfW(old, L"%s.old", done[k].target); append_utf8(aside, (n + 1) * 3300, old, ""); lstrcatA(aside, "\n"); }
        /* the running program under another name (a renamed release): set aside too, so one program is left */
        if (GetModuleFileNameW(NULL, running, 1024) && lstrlenW(running) < 1000) {
            wchar_t fresh[1100];
            wsprintfW(fresh, L"%s\\%s", program, files[exe].rel);
            if (lstrcmpiW(running, fresh) && !_wcsnicmp(running, program, plen) && running[plen] == L'\\') {
                wsprintfW(old, L"%s.old", running);
                if (MoveFileExW(running, old, MOVEFILE_REPLACE_EXISTING)) { append_utf8(aside, (n + 1) * 3300, old, ""); lstrcatA(aside, "\n"); }
            }
        }
        CreateDirectoryW(dir, NULL);
        wsprintfW(list_path, L"%s\\set aside.txt", dir);
        f = CreateFileW(list_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD wrote;
            WriteFile(f, aside, (DWORD)lstrlenA(aside), &wrote, NULL);
            CloseHandle(f);
        }
        free(aside);
    }
    DeleteFileW(zip_path);
    if (exe_size > 0) {
        wchar_t fresh[1100];
        wsprintfW(fresh, L"%s\\%s", program, files[exe].rel);
        lstrcpynW(exe_out, fresh, exe_size);
    }
    free(done); free_entries(files, count);
    return 1;
}

__declspec(dllexport) int shodan_launch(const wchar_t *exe_in) {
    wchar_t exe[1024], folder[1024], line[1100];
    wchar_t *cut;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    if (lstrlenW(exe_in) >= 1000) return 0;
    lstrcpyW(exe, exe_in); slashes(exe);
    lstrcpyW(folder, exe);
    cut = wcsrchr(folder, L'\\');
    if (!cut) return 0;
    *cut = 0;
    wsprintfW(line, L"\"%s\"", exe);
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessW(exe, line, NULL, NULL, FALSE, 0, NULL, folder, &si, &pi)) return 0;
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 1;
}

__declspec(dllexport) int shodan_cleanup(const wchar_t *dir_in) {
    wchar_t dir[1024], list_path[1100], path[1024], pattern[1100], item[1100];
    unsigned char *text;
    size_t size = 0, k, start = 0;
    char *left;
    int left_any = 0;
    WIN32_FIND_DATAW e;
    HANDLE find, f;
    if (lstrlenW(dir_in) >= 1000) return 0;
    lstrcpyW(dir, dir_in); slashes(dir);
    if (!exists(dir)) return 1;
    wsprintfW(list_path, L"%s\\set aside.txt", dir);
    text = read_all(list_path, &size);
    left = (char *)calloc(size + 2, 1);
    if (text && left) {
        for (k = 0; k <= size; k++) {
            if (k == size || text[k] == '\n' || text[k] == '\r') {
                int len = (int)(k - start);
                if (len > 0 && len < 3000) {
                    char line[3000];
                    memcpy(line, text + start, len); line[len] = 0;
                    if (MultiByteToWideChar(CP_UTF8, 0, line, -1, path, 1024)) {
                        int plen = lstrlenW(path);
                        slashes(path);
                        /* only what an update set aside */
                        if (plen > 4 && !lstrcmpiW(path + plen - 4, L".old") && exists(path) && !DeleteFileW(path)) {
                            lstrcatA(left, line); lstrcatA(left, "\n"); left_any = 1;
                        }
                    }
                }
                start = k + 1;
            }
        }
    }
    free(text);
    if (!left_any) { free(left); remove_tree(dir); return !exists(dir); }
    /* still in use (the old program closing): everything else goes, the list keeps what is left */
    wsprintfW(pattern, L"%s\\*", dir);
    find = FindFirstFileW(pattern, &e);
    if (find != INVALID_HANDLE_VALUE) {
        do {
            if (!lstrcmpW(e.cFileName, L".") || !lstrcmpW(e.cFileName, L"..") || !lstrcmpiW(e.cFileName, L"set aside.txt")) continue;
            wsprintfW(item, L"%s\\%s", dir, e.cFileName);
            if (e.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) remove_tree(item); else DeleteFileW(item);
        } while (FindNextFileW(find, &e));
        FindClose(find);
    }
    f = CreateFileW(list_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD wrote;
        WriteFile(f, left, (DWORD)lstrlenA(left), &wrote, NULL);
        CloseHandle(f);
    }
    free(left);
    return 0;
}
