#pragma once
BOOL GetCmdPathW(
    WCHAR* out, 
    DWORD outSize)
{
    if (!out || outSize < MAX_PATH)
        return FALSE;

    UINT len = GetSystemDirectoryW(out, outSize);
    if (len == 0 || len >= outSize)
        return FALSE;

    if (out[len - 1] != L'\\') {
        if (len + 1 >= outSize)
            return FALSE;
        out[len++] = L'\\';
        out[len] = 0;
    }

    const WCHAR tail[] = L"cmd.exe";
    for (UINT i = 0; tail[i] != 0; i++) {
        if (len + i + 1 >= outSize)
            return FALSE;
        out[len + i] = tail[i];
        out[len + i + 1] = 0;
    }

    return TRUE;
}

BOOL ExtractFileNameW(
    const WCHAR* fullPath,
    WCHAR* out,
    SIZE_T outSize)
{
    if (!fullPath || !out || outSize == 0)
        return FALSE;

    const WCHAR* lastSlash = fullPath;
    const WCHAR* p = fullPath;
    while (*p)
    {
        if (*p == L'\\' || *p == L'/')
            lastSlash = p + 1;
        p++;
    }

    SIZE_T i = 0;
    while (lastSlash[i] && i + 1 < outSize)
    {
        out[i] = lastSlash[i];
        i++;
    }

    if (i >= outSize)
        return FALSE;

    out[i] = 0;
    return TRUE;
}