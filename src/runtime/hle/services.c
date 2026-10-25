#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <SDL.h>

#include "hle.h"

#define ORBIS_OK 0

#define SAVE_DATA_ERROR_NOT_FOUND 0x809F0008u
#define SAVE_DATA_ERROR_BUSY 0x809F0003u
#define MOUNTS 16

static char mounts[MOUNTS][32];
static SDL_SpinLock mount_lock;

int hle_savedata_path(const char* p, char* out, size_t cap) {
    int n;
    int len = 0;
    if (sscanf(p, "/savedata%d%n", &n, &len) != 1 || n < 0 || n >= MOUNTS || (p[len] && p[len] != '/')) {
        return 0;
    }
    snprintf(out, cap, "%s/%s%s", rt_save_dir(), mounts[n][0] ? mounts[n] : "default", p + len);
    return 1;
}

HLE(sceSaveDataInitialize3) { RET(c, ORBIS_OK); }
HLE(sceSaveDataMount2) {
    const uint8_t* m = ARGP(c, 0);
    uint64_t dir_addr;
    memcpy(&dir_addr, m + 8, 8);
    const char* dir = dir_addr ? GSTR(dir_addr) : "default";
    SDL_AtomicLock(&mount_lock);
    int n = 0;
    while (n < MOUNTS && mounts[n][0]) {
        n++;
    }
    if (n == MOUNTS) {
        SDL_AtomicUnlock(&mount_lock);
        RET(c, (int64_t)(int32_t)SAVE_DATA_ERROR_BUSY);
        return;
    }
    snprintf(mounts[n], sizeof mounts[n], "%s", dir);
    SDL_AtomicUnlock(&mount_lock);
    char path[1024];
    mkdir(rt_save_dir(), 0777);
    snprintf(path, sizeof path, "%s/%s", rt_save_dir(), mounts[n]);
    mkdir(path, 0777);
    uint8_t* r = ARGP(c, 1);
    memset(r, 0, 64);
    snprintf((char*)r, 16, "/savedata%d", n);
    LOG("save data %s mounted at %s", mounts[n], (char*)r);
    RET(c, ORBIS_OK);
}
HLE(sceSaveDataUmount) {
    char path[64];
    snprintf(path, sizeof path, "%s", GSTR(ARG(c, 0)));
    int n;
    if (sscanf(path, "/savedata%d", &n) == 1 && n >= 0 && n < MOUNTS) {
        SDL_AtomicLock(&mount_lock);
        mounts[n][0] = 0;
        SDL_AtomicUnlock(&mount_lock);
    }
    RET(c, ORBIS_OK);
}
HLE(sceSaveDataDirNameSearch) {
    const uint8_t* cond = ARGP(c, 0);
    uint8_t* r = ARGP(c, 1);
    uint64_t dir_addr, names;
    memcpy(&dir_addr, cond + 16, 8);
    memcpy(&names, r + 8, 8);
    uint32_t names_num, hits = 0;
    memcpy(&names_num, r + 16, 4);
    if (dir_addr) {
        char path[1024];
        snprintf(path, sizeof path, "%s/%s", rt_save_dir(), GSTR(dir_addr));
        struct stat st;
        if (!stat(path, &st) && S_ISDIR(st.st_mode)) {
            hits = 1;
            if (names && names_num) {
                memset(G(names), 0, 32);
                snprintf(G(names), 32, "%s", GSTR(dir_addr));
            }
        }
    }
    memcpy(r, &hits, 4);
    const uint32_t set = hits < names_num ? hits : names_num;
    memcpy(r + 20, &set, 4);
    RET(c, ORBIS_OK);
}
HLE(sceSaveDataGetMountInfo) {
    uint64_t* info = ARGP(c, 1);
    info[0] = 1 << 16;
    info[1] = 1 << 15;
    RET(c, ORBIS_OK);
}
HLE(sceSaveDataGetParam) { RET(c, ORBIS_OK); }
HLE(sceSaveDataSetParam) { RET(c, ORBIS_OK); }
HLE(sceSaveDataSaveIcon) { RET(c, ORBIS_OK); }
HLE(sceSaveDataLoadIcon) { RET(c, (int64_t)(int32_t)SAVE_DATA_ERROR_NOT_FOUND); }
HLE(sceSaveDataDelete) { RET(c, ORBIS_OK); }

#define DIALOG_STATUS_FINISHED 3

HLE(dialog_ok) { RET(c, ORBIS_OK); }
HLE(dialog_finished) { RET(c, DIALOG_STATUS_FINISHED); }
HLE(dialog_result) {
    if (ARG(c, 0)) {
        memset(ARGP(c, 0) + 4, 0, 4);
    }
    RET(c, ORBIS_OK);
}

#define NP_ERROR_SIGNED_OUT 0x80550006u
#define NP_ERROR_NOT_SIGNED_UP 0x80550004u

HLE(np_signed_out) { RET(c, (int64_t)(int32_t)NP_ERROR_SIGNED_OUT); }
HLE(np_request) {
    static int next = 1;
    RET(c, next++);
}
HLE(np_ok) { RET(c, ORBIS_OK); }
HLE(sceNpGetAccountCountryA) {
    if (ARG(c, 1)) {
        memset(ARGP(c, 1), 0, 4);
        memcpy(ARGP(c, 1), "us", 2);
    }
    RET(c, (int64_t)(int32_t)NP_ERROR_SIGNED_OUT);
}
HLE(sceNpTrophyCreateContext) {
    if (ARG(c, 0)) {
        *(int32_t*)ARGP(c, 0) = 1;
    }
    RET(c, ORBIS_OK);
}
HLE(sceNpTrophyCreateHandle) {
    if (ARG(c, 0)) {
        *(int32_t*)ARGP(c, 0) = 1;
    }
    RET(c, ORBIS_OK);
}
HLE(sceNpTrophyUnlockTrophy) {
    LOG("trophy %d unlocked", (int)ARG(c, 2));
    if (ARG(c, 3)) {
        *(int32_t*)ARGP(c, 3) = -1;
    }
    RET(c, ORBIS_OK);
}

#define NET_ERROR_ENETDOWN 0x80410132u
#define NET_CTL_ERROR_NOT_CONNECTED 0x80412108u

static int32_t net_errno = 50;
HLE(net_down) { RET(c, (int64_t)(int32_t)NET_ERROR_ENETDOWN); }
HLE(sceNetErrnoLoc) { RET(c, H(&net_errno)); }
HLE(sceNetPoolCreate) { RET(c, 1); }
HLE(sceNetHtonl) { RET(c, __builtin_bswap32((uint32_t)ARG(c, 0))); }
HLE(sceNetHtons) { RET(c, __builtin_bswap16((uint16_t)ARG(c, 0))); }
HLE(sceNetGetMacAddress) {
    static const uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    memcpy(ARGP(c, 0), mac, 6);
    RET(c, ORBIS_OK);
}
HLE(sceNetCtlGetInfo) { RET(c, (int64_t)(int32_t)NET_CTL_ERROR_NOT_CONNECTED); }
HLE(http_init) {
    static int next = 1;
    RET(c, next++);
}

HLE(sceRandomGetRandomNumber) {
    uint8_t* p = ARGP(c, 0);
    for (uint64_t i = 0; i < ARG(c, 1); i++) {
        p[i] = (uint8_t)rand();
    }
    RET(c, ORBIS_OK);
}
HLE(services_ok) { RET(c, ORBIS_OK); }
HLE(sceAppContentAppParamGetInt) {
    if (ARG(c, 1)) {
        *(int32_t*)ARGP(c, 1) = 0;
    }
    RET(c, ORBIS_OK);
}

static const char* const addcont_labels[] = {"ALLLEG0000000000", "BRAWLHALLAALLFND", "BRAWLHALLAALLFN2"};
HLE(sceAppContentGetAddcontInfoList) {
    const char* off = getenv("BH_NO_DLC");
    const uint32_t have = off && *off && *off != '0' ? 0 : sizeof addcont_labels / sizeof *addcont_labels;
    uint8_t* list = ARGP(c, 1);
    uint32_t n = have;
    if (list && ARG(c, 2)) {
        n = have < (uint32_t)ARG(c, 2) ? have : (uint32_t)ARG(c, 2);
        for (uint32_t i = 0; i < n; i++) {
            memset(list + 24 * i, 0, 24);
            memcpy(list + 24 * i, addcont_labels[i], 16);
        }
    }
    if (ARG(c, 3)) {
        *(uint32_t*)ARGP(c, 3) = n;
    }
    LOG("app content: %u add-ons listed", n);
    RET(c, ORBIS_OK);
}
HLE(sceAudio3dInitialize) { RET(c, (int64_t)(int32_t)0x80EA0001u); }

HLE(device_absent) { RET(c, (int64_t)(int32_t)0x80DF0003u); }

const HleFunc hle_services_funcs[] = {
    HLE_FUNC(sceSaveDataInitialize3), HLE_FUNC(sceSaveDataMount2), HLE_FUNC(sceSaveDataUmount),
    HLE_FUNC(sceSaveDataDirNameSearch), HLE_FUNC(sceSaveDataGetMountInfo), HLE_FUNC(sceSaveDataGetParam),
    HLE_FUNC(sceSaveDataSetParam), HLE_FUNC(sceSaveDataSaveIcon), HLE_FUNC(sceSaveDataLoadIcon),
    HLE_FUNC(sceSaveDataDelete),
    HLE_FUNC_AS("sceCommonDialogInitialize", dialog_ok),
    HLE_FUNC_AS("sceMsgDialogInitialize", dialog_ok), HLE_FUNC_AS("sceMsgDialogOpen", dialog_ok),
    HLE_FUNC_AS("sceMsgDialogUpdateStatus", dialog_finished), HLE_FUNC_AS("sceMsgDialogGetResult", dialog_result),
    HLE_FUNC_AS("sceMsgDialogTerminate", dialog_ok),
    HLE_FUNC_AS("sceSaveDataDialogInitialize", dialog_ok), HLE_FUNC_AS("sceSaveDataDialogOpen", dialog_ok),
    HLE_FUNC_AS("sceSaveDataDialogUpdateStatus", dialog_finished),
    HLE_FUNC_AS("sceSaveDataDialogGetResult", dialog_result), HLE_FUNC_AS("sceSaveDataDialogTerminate", dialog_ok),
    HLE_FUNC_AS("sceImeDialogInit", dialog_ok), HLE_FUNC_AS("sceImeDialogGetStatus", dialog_finished),
    HLE_FUNC_AS("sceImeDialogGetResult", dialog_result), HLE_FUNC_AS("sceImeDialogTerm", dialog_ok),
    HLE_FUNC_AS("sceNpProfileDialogInitialize", dialog_ok), HLE_FUNC_AS("sceNpProfileDialogOpenA", dialog_ok),
    HLE_FUNC_AS("sceNpProfileDialogUpdateStatus", dialog_finished), HLE_FUNC_AS("sceNpProfileDialogTerminate", dialog_ok),
    HLE_FUNC_AS("sceNpCommerceDialogInitialize", dialog_ok), HLE_FUNC_AS("sceNpCommerceDialogOpen", dialog_ok),
    HLE_FUNC_AS("sceNpCommerceDialogUpdateStatus", dialog_finished),
    HLE_FUNC_AS("sceNpCommerceDialogGetResult", dialog_result), HLE_FUNC_AS("sceNpCommerceDialogTerminate", dialog_ok),
    HLE_FUNC_AS("sceNpCommerceHidePsStoreIcon", dialog_ok),
    HLE_FUNC_AS("sceWebBrowserDialogInitialize", dialog_ok), HLE_FUNC_AS("sceWebBrowserDialogOpen", dialog_ok),
    HLE_FUNC_AS("sceWebBrowserDialogOpenForPredeterminedContent", dialog_ok),
    HLE_FUNC_AS("sceWebBrowserDialogUpdateStatus", dialog_finished),
    HLE_FUNC_AS("sceWebBrowserDialogGetStatus", dialog_finished), HLE_FUNC_AS("sceWebBrowserDialogClose", dialog_ok),
    HLE_FUNC_AS("sceWebBrowserDialogTerminate", dialog_ok), HLE_FUNC_AS("sceInvitationDialogInitialize", dialog_ok),
    HLE_FUNC_AS("sceNpCheckNpAvailabilityA", np_signed_out), HLE_FUNC_AS("sceNpCheckPlus", np_signed_out),
    HLE_FUNC_AS("sceNpGetAccountIdA", np_signed_out), HLE_FUNC_AS("sceNpGetNpId", np_signed_out),
    HLE_FUNC_AS("sceNpGetAccountLanguageA", np_signed_out), HLE_FUNC_AS("sceNpGetAccountDateOfBirthA", np_signed_out),
    HLE_FUNC(sceNpGetAccountCountryA),
    HLE_FUNC_AS("sceNpCreateRequest", np_request), HLE_FUNC_AS("sceNpCreateAsyncRequest", np_request),
    HLE_FUNC_AS("sceNpDeleteRequest", np_ok), HLE_FUNC_AS("sceNpPollAsync", np_signed_out),
    HLE_FUNC_AS("sceNpSetContentRestriction", np_ok),
    HLE_FUNC_AS("sceNpAuthCreateRequest", np_request), HLE_FUNC_AS("sceNpAuthCreateAsyncRequest", np_request),
    HLE_FUNC_AS("sceNpAuthDeleteRequest", np_ok), HLE_FUNC_AS("sceNpAuthAbortRequest", np_ok),
    HLE_FUNC_AS("sceNpAuthGetAuthorizationCodeA", np_signed_out), HLE_FUNC_AS("sceNpAuthPollAsync", np_signed_out),
    HLE_FUNC_AS("sceNpWebApiInitialize", np_request), HLE_FUNC_AS("sceNpWebApiCreateContextA", np_signed_out),
    HLE_FUNC_AS("sceNpWebApiTerminate", np_ok), HLE_FUNC_AS("sceNpWebApiDeleteContext", np_ok),
    HLE_FUNC_AS("sceNpWordFilterCreateTitleCtxA", np_signed_out),
    HLE_FUNC(sceNpTrophyCreateContext), HLE_FUNC(sceNpTrophyCreateHandle), HLE_FUNC_AS("sceNpTrophyRegisterContext", np_ok),
    HLE_FUNC_AS("sceNpTrophyDestroyHandle", np_ok), HLE_FUNC(sceNpTrophyUnlockTrophy),
    HLE_FUNC(sceNetErrnoLoc), HLE_FUNC(sceNetPoolCreate), HLE_FUNC_AS("sceNetPoolDestroy", np_ok),
    HLE_FUNC(sceNetHtonl), HLE_FUNC(sceNetHtons), HLE_FUNC_AS("sceNetNtohs", sceNetHtons), HLE_FUNC(sceNetGetMacAddress),
    HLE_FUNC_AS("sceNetSocket", net_down), HLE_FUNC_AS("sceNetResolverCreate", net_down),
    HLE_FUNC_AS("sceNetEpollCreate", net_down), HLE_FUNC_AS("sceNetConnect", net_down),
    HLE_FUNC_AS("sceNetResolverStartNtoa", net_down), HLE_FUNC_AS("sceNetResolverStartAton", net_down),
    HLE_FUNC(sceNetCtlGetInfo),
    HLE_FUNC_AS("sceHttpInit", http_init), HLE_FUNC_AS("sceSslInit", http_init),
    HLE_FUNC_AS("sceHttpCreateTemplate", net_down), HLE_FUNC_AS("sceHttpCreateConnection", net_down),
    HLE_FUNC_AS("sceHttpCreateRequestWithURL", net_down), HLE_FUNC_AS("sceHttpSendRequest", net_down),
    HLE_FUNC(sceRandomGetRandomNumber), HLE_FUNC_AS("sceUltInitialize", services_ok), HLE_FUNC_AS("sceUltFinalize", services_ok),
    HLE_FUNC_AS("sceAppContentInitialize", services_ok), HLE_FUNC(sceAppContentAppParamGetInt),
    HLE_FUNC(sceAppContentGetAddcontInfoList), HLE_FUNC(sceAudio3dInitialize),
    HLE_FUNC_AS("sceMoveGetDeviceInfo", device_absent), HLE_FUNC_AS("sceMoveSetVibration", services_ok),
    HLE_FUNC_AS("sceRtcSetTick", services_ok),
    {NULL, NULL},
};
