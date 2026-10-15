#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PEER "74.125.250.129"
#define PEER_PORT 19302
#define WAN "192.0.2.2"
static const uint8_t cookie[4] = {0x21,0x12,0xa4,0x42};
static unsigned u16(const uint8_t *p) { return (unsigned)p[0]*256+p[1]; }
static long long now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) return -1;
    return (long long)t.tv_sec*1000+t.tv_nsec/1000000;
}
/* Ignore other transactions; malformed replies for our transaction fail closed. */
static int parse(const uint8_t *p, size_t n, const uint8_t tx[12], struct in_addr *mapped, unsigned *port) {
    if (n<20 || memcmp(p+8,tx,12)) return 0;
    if (u16(p)!=0x0101 || memcmp(p+4,cookie,4) || u16(p+2)%4 || u16(p+2)!=n-20) return -1;
    int found=0;
    for (size_t at=20; at<n;) {
        if (n-at<4) return -1;
        unsigned kind=u16(p+at), len=u16(p+at+2);
        at+=4;
        size_t padded=(len+3u)&~3u;
        if (padded>n-at) return -1;
        if (kind==0x0020) {
            if (found || len!=8 || p[at]!=0 || p[at+1]!=1) return -1;
            *port=u16(p+at+2)^0x2112;
            if (!*port) return -1;
            uint8_t ip[4];
            for (unsigned i=0;i<4;i++) ip[i]=p[at+4+i]^cookie[i];
            memcpy(&mapped->s_addr,ip,4); found=1;
        } else if (kind==0x0001) {
            if (len!=8 || p[at]!=0 || p[at+1]!=1 || !u16(p+at+2)) return -1;
        } else if (kind<0x8000) return -1;
        at+=padded;
    }
    return found?1:-1;
}
static void selftest(void) {
    const uint8_t tx[12]={1,2,3,4,5,6,7,8,9,10,11,12};
    uint8_t p[64]={1,1,0,12,0x21,0x12,0xa4,0x42};
    memcpy(p+8,tx,12); p[20]=0; p[21]=0x20; p[23]=8; p[25]=1;
    unsigned expected=12600, port=0;
    p[26]=(expected^0x2112)>>8; p[27]=(expected^0x2112)&255;
    struct in_addr want,ip;
    assert(inet_pton(AF_INET,WAN,&want)==1);
    for(unsigned i=0;i<4;i++) p[28+i]=((uint8_t *)&want.s_addr)[i]^cookie[i];
    assert(parse(p,32,tx,&ip,&port)==1 && port==expected && ip.s_addr==want.s_addr);
    assert(parse(p,19,tx,&ip,&port)==0);
    p[8]^=1; assert(parse(p,32,tx,&ip,&port)==0); p[8]^=1;
    p[4]^=1; assert(parse(p,32,tx,&ip,&port)==-1); p[4]^=1;
    p[1]=0x11; assert(parse(p,32,tx,&ip,&port)==-1); p[1]=1;
    p[3]=11; assert(parse(p,32,tx,&ip,&port)==-1); p[3]=12;
    assert(parse(p,31,tx,&ip,&port)==-1);
    p[23]=9; assert(parse(p,32,tx,&ip,&port)==-1); p[23]=8;
    p[24]=1; assert(parse(p,32,tx,&ip,&port)==-1); p[24]=0;
    p[25]=2; assert(parse(p,32,tx,&ip,&port)==-1); p[25]=1;
    p[21]=1; assert(parse(p,32,tx,&ip,&port)==-1); p[21]=0x20;
    memcpy(p+32,p+20,12); p[3]=24; assert(parse(p,44,tx,&ip,&port)==-1);
    p[32]=0x80; p[33]=0x22; p[34]=0; p[35]=1; p[36]=0x41; p[3]=20;
    assert(parse(p,40,tx,&ip,&port)==1);
    p[32]=0; p[33]=1; assert(parse(p,40,tx,&ip,&port)==-1); p[32]=0x80; p[33]=0x22;
    p[35]=8; assert(parse(p,40,tx,&ip,&port)==-1);
    p[3]=0; assert(parse(p,20,tx,&ip,&port)==-1);
    puts("STUN selftest passed");
}
int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1],"--selftest")) { selftest(); return 0; }
    if (argc!=2 || strlen(argv[1])!=5 || strspn(argv[1],"0123456789")!=5) return 2;
    unsigned source=(unsigned)strtoul(argv[1],NULL,10);
    if (source<12600 || source>12659) return 2;
    long long start=now_ms(), end=start+4000;
    if (start<0) return 1;
    const char *failure="setup";
    int fd=-1, random=-1, success=0;
    unsigned mapped_port=0, ignored=0;
    struct sockaddr_in local={.sin_family=AF_INET,.sin_port=htons(source)};
    struct sockaddr_in peer={.sin_family=AF_INET,.sin_port=htons(PEER_PORT)};
    struct in_addr mapped={0};
    char local_ip[INET_ADDRSTRLEN]="", mapped_ip[INET_ADDRSTRLEN]="";
    uint8_t request[20]={0,1,0,0,0x21,0x12,0xa4,0x42};
    random=open("/dev/urandom",O_RDONLY);
    if (random<0) goto done;
    size_t have=0;
    while(have<12) {
        ssize_t n=read(random,request+8+have,12-have);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) goto done;
        have+=(size_t)n;
    }
    close(random); random=-1;
    fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd<0 || bind(fd,(struct sockaddr *)&local,sizeof(local)) || inet_pton(AF_INET,PEER,&peer.sin_addr)!=1 || connect(fd,(struct sockaddr *)&peer,sizeof(peer))) goto done;
    socklen_t len=sizeof(local);
    if (getsockname(fd,(struct sockaddr *)&local,&len) || !inet_ntop(AF_INET,&local.sin_addr,local_ip,sizeof(local_ip))) goto done;
    if (send(fd,request,sizeof(request),0)!=(ssize_t)sizeof(request)) goto done;
    failure="timeout";
    for (;;) {
        long long now=now_ms();
        if (now<0) { failure="clock"; break; }
        if (now>=end) break;
        struct pollfd pollfd={.fd=fd,.events=POLLIN};
        int ready=poll(&pollfd,1,(int)(end-now));
        if (ready<0 && errno==EINTR) continue;
        if (ready<0) { failure="receive"; break; }
        if (!ready) break;
        uint8_t response[2048];
        ssize_t n=recv(fd,response,sizeof(response),MSG_DONTWAIT|MSG_TRUNC);
        if (n<0 && (errno==EINTR || errno==EAGAIN)) continue;
        if (n<0) { failure="receive"; break; }
        if ((size_t)n>sizeof(response)) { failure="oversize"; break; }
        int valid=parse(response,(size_t)n,request+8,&mapped,&mapped_port);
        if (!valid) { ignored++; continue; }
        if (valid<0) { failure="invalid_stun"; break; }
        if (!inet_ntop(AF_INET,&mapped,mapped_ip,sizeof(mapped_ip))) break;
        success=1; failure=""; break;
    }
done:
    if (random>=0) close(random);
    if (fd>=0) close(fd);
    int route=success && !strcmp(local_ip,WAN) && !strcmp(mapped_ip,WAN) && mapped_port==source;
    if (success && !route) failure="route";
    long long elapsed=now_ms()-start;
    printf("{\"binding_success\":%s,\"route_verified\":%s,\"remote_ip\":\"%s\",\"remote_port\":%d,\"local_ip\":\"%s\",\"local_port\":%u,\"mapped_ip\":\"%s\",\"mapped_port\":%u,\"time_total\":%.3f,\"ignored_transactions\":%u,\"failure\":\"%s\"}\n",success?"true":"false",route?"true":"false",PEER,PEER_PORT,local_ip,source,mapped_ip,mapped_port,elapsed<0?0:elapsed/1000.0,ignored,failure);
    return success && route?0:1;
}
