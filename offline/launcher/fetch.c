/* SHODAN Stat Editor Offline: HTTPS downloads for the updater, on a thread of their own (the window keeps
   running). WinHTTP follows GitHub's redirects to its download host; nothing is cached.
   shodan_fetch(url, path) starts one and returns a handle; shodan_fetch_result(handle) is -1 while it runs, then
   the HTTP status (200: the file is complete, its folder made if missing) or a negative error, and frees the
   handle. */
#include <windows.h>
#include <winhttp.h>

typedef struct {
    HANDLE thread;
    volatile LONG result;
    wchar_t url[2048], path[1024];
} fetch_job;

static LONG fetch_run(fetch_job *job) {
    URL_COMPONENTS parts;
    wchar_t host[256], object[2048];
    HINTERNET session = NULL, connect = NULL, request = NULL;
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD status = 0, size = sizeof(status), got = 0;
    char buffer[65536];
    LONG result = -2;

    ZeroMemory(&parts, sizeof(parts));
    parts.dwStructSize = sizeof(parts);
    parts.lpszHostName = host; parts.dwHostNameLength = 256;
    parts.lpszUrlPath = object; parts.dwUrlPathLength = 2048;
    if (!WinHttpCrackUrl(job->url, 0, 0, &parts) || parts.nScheme != INTERNET_SCHEME_HTTPS) return -3;
    session = WinHttpOpen(L"SHODAN-Stat-Editor-Offline", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) session = WinHttpOpen(L"SHODAN-Stat-Editor-Offline", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return -4;
    WinHttpSetTimeouts(session, 10000, 10000, 15000, 30000);
    connect = WinHttpConnect(session, host, parts.nPort, 0);
    if (connect) request = WinHttpOpenRequest(connect, L"GET", object, NULL, WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (request && WinHttpSendRequest(request, L"Accept: application/vnd.github+json, application/octet-stream\r\n",
                                      (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
        && WinHttpReceiveResponse(request, NULL)
        && WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX)) {
        result = (LONG)status;
        if (status == 200) {
            wchar_t folder[1024];
            int k;
            for (k = 0; job->path[k] && k < 1023; k++) {   /* the folders on the way to the file */
                folder[k] = job->path[k];
                if (job->path[k] == L'\\' && k > 0 && job->path[k - 1] != L':') { folder[k] = 0; CreateDirectoryW(folder, NULL); folder[k] = L'\\'; }
            }
            file = CreateFileW(job->path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (file == INVALID_HANDLE_VALUE) result = -5;
            else {
                for (;;) {
                    DWORD wrote = 0;
                    if (!WinHttpReadData(request, buffer, sizeof(buffer), &got)) { result = -6; break; }
                    if (got == 0) break;
                    if (!WriteFile(file, buffer, got, &wrote, NULL) || wrote != got) { result = -7; break; }
                }
                CloseHandle(file);
                if (result != 200) DeleteFileW(job->path);
            }
        }
    }
    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return result;
}

static DWORD WINAPI fetch_thread(LPVOID arg) {
    fetch_job *job = (fetch_job *)arg;
    InterlockedExchange(&job->result, fetch_run(job));
    return 0;
}

__declspec(dllexport) void *shodan_fetch(const wchar_t *url, const wchar_t *path) {
    fetch_job *job = (fetch_job *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(fetch_job));
    if (!job) return NULL;
    if (lstrlenW(url) >= 2048 || lstrlenW(path) >= 1024) { HeapFree(GetProcessHeap(), 0, job); return NULL; }
    lstrcpyW(job->url, url);
    lstrcpyW(job->path, path);
    job->result = -1;
    job->thread = CreateThread(NULL, 0, fetch_thread, job, 0, NULL);
    if (!job->thread) { HeapFree(GetProcessHeap(), 0, job); return NULL; }
    return job;
}

__declspec(dllexport) int shodan_fetch_result(void *handle) {
    fetch_job *job = (fetch_job *)handle;
    LONG result;
    if (!job) return -8;
    if (WaitForSingleObject(job->thread, 0) != WAIT_OBJECT_0) return -1;
    result = job->result;
    CloseHandle(job->thread);
    HeapFree(GetProcessHeap(), 0, job);
    return (int)result;
}
