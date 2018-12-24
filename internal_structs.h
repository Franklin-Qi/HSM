#ifndef __INTERNAL_STRUCTS_SDF4CUSTSJJ1310_H__
#define __INTERNAL_STRUCTS_SDF4CUSTSJJ1310_H__


/*typedef struct Device_struct{
    unsigned int status; // 0,未初始化; 1,已初始化; 2,已经释放;
    int sockfd;
    char ip[16];
    unsigned int port;
}Devicestruct;*/

typedef struct Device_struct{
    unsigned int status; // 0,未初始化; 1,已初始化; 2,已经释放;
    int sockfd;
    char ip[16];
    unsigned int port;
    int msgHeadLen;
}Devicestruct;

typedef struct HashState_st{
    unsigned int m_uiMechanism;
    unsigned int datalength;
    unsigned char *pucData;
    unsigned int hashlength;
    unsigned char *pucHash;
}HashCtx;

//
typedef struct Session_struct{
    int status; // 0,未初始化; 1,已初始化; 2,已经释放;
    Devicestruct *device;
    HashCtx hashCtx;
}Sessionstruct;

#endif  // __INTERNAL_STRUCTS_SDF06_H__

