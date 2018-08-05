#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdlib.h>

#include "tunnel.c"

int tun_new(const char *_name) 
{
    int fd;
    struct ifreq ifr;
    struct ifconf ifc;

    if((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return ERR_OPEN_FAILED;
    }

    if(strlen(_name) + 1 > IFNAMSIZ) {
        return ERR_NAME_TOO_LONG;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN;
    strncpy(ifr.ifr_name, _name, IFNAMSIZ);

    if( ioctl(fd, TUNSETIFF, (void*)&ifr) < 0 ) {
        return ERR_CONFIG;
    }

    return fd;
}

void tun_free(int _fd) 
{
    close(_fd);
}

ssize_t tun_read(int _fd, void* _buffer, ssize_t _buf_size) 
{
    return read(_fd, _buffer, _buf_size); 
}

ssize_t tun_write(int _fd, void* _buffer, ssize_t _buf_size) 
{
    return write(_fd, _buffer, _buf_size);
}




