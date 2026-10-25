#include <stdio.h>
#include <string.h>

#include <SDL.h>

#include "hle.h"

#define ORBIS_OK 0

#define USER_ID 1

HLE(sceUserServiceInitialize) { RET(c, ORBIS_OK); }
HLE(sceUserServiceGetInitialUser) {
    *(int32_t*)ARGP(c, 0) = USER_ID;
    RET(c, ORBIS_OK);
}
HLE(sceUserServiceGetLoginUserIdList) {
    int32_t* list = ARGP(c, 0);
    list[0] = USER_ID;
    list[1] = list[2] = list[3] = -1;
    RET(c, ORBIS_OK);
}
HLE(sceUserServiceGetUserName) {
    snprintf(ARGP(c, 1), ARG(c, 2), "%s", "Player");
    RET(c, ORBIS_OK);
}
HLE(sceUserServiceTerminate) { RET(c, ORBIS_OK); }
HLE(sceUserServiceGetEvent) { RET(c, 0x80960007); }

enum { PARAM_LANG = 1, PARAM_DATE_FORMAT, PARAM_TIME_FORMAT, PARAM_TIME_ZONE, PARAM_SUMMERTIME,
       PARAM_GAME_PARENTAL_LEVEL = 7, PARAM_ENTER_BUTTON_ASSIGN = 1000 };

HLE(sceSystemServiceParamGetInt) {
    const int id = (int)ARG(c, 0);
    int32_t v = 0;
    switch (id) {
    case PARAM_LANG: v = 1; break;
    case PARAM_ENTER_BUTTON_ASSIGN: v = 1; break;
    default: break;
    }
    *(int32_t*)ARGP(c, 1) = v;
    RET(c, ORBIS_OK);
}
HLE(sceSystemServiceGetStatus) {
    uint8_t* s = ARGP(c, 0);
    memset(s, 0, 9);
    s[6] = 1;
    RET(c, ORBIS_OK);
}
HLE(sceSystemServiceHideSplashScreen) { RET(c, ORBIS_OK); }
HLE(sceSystemServiceGetDisplaySafeAreaInfo) {
    const float ratio = 1.0f;
    memset(ARGP(c, 0), 0, 132);
    memcpy(ARGP(c, 0), &ratio, 4);
    RET(c, ORBIS_OK);
}
HLE(sceSystemServiceReceiveEvent) { RET(c, 0x80A10003);   }
HLE(sceSysmoduleLoadModule) { RET(c, ORBIS_OK); }
HLE(sceSysmoduleUnloadModule) { RET(c, ORBIS_OK); }
HLE(sceSysmoduleIsLoaded) { RET(c, ORBIS_OK); }

HLE(sceRtcGetCurrentTick) {
    const uint64_t unix_us = (uint64_t)SDL_GetTicks64() * 1000;
    *(uint64_t*)ARGP(c, 0) = unix_us + 62135596800000000ull + 1500000000000000ull;
    RET(c, ORBIS_OK);
}

const HleFunc hle_sce_funcs[] = {
    HLE_FUNC(sceUserServiceInitialize), HLE_FUNC(sceUserServiceGetInitialUser),
    HLE_FUNC(sceUserServiceGetLoginUserIdList), HLE_FUNC(sceUserServiceGetEvent),
    HLE_FUNC(sceSystemServiceParamGetInt), HLE_FUNC(sceSystemServiceGetStatus),
    HLE_FUNC(sceSystemServiceHideSplashScreen), HLE_FUNC(sceSystemServiceReceiveEvent),
    HLE_FUNC(sceSysmoduleLoadModule), HLE_FUNC(sceSysmoduleUnloadModule), HLE_FUNC(sceSysmoduleIsLoaded),
    HLE_FUNC(sceRtcGetCurrentTick), HLE_FUNC(sceUserServiceGetUserName), HLE_FUNC(sceUserServiceTerminate),
    HLE_FUNC(sceSystemServiceGetDisplaySafeAreaInfo),
    {NULL, NULL},
};
