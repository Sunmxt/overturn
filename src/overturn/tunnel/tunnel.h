// tunnel.h

const int ERR_OPEN_FAILED       = -1;
const int ERR_NAME_TOO_LONG     = -2;
const int ERR_CONFIG            = -3;

int tun_new(const char *_name);
int tun_free(int _fd);
ssize_t tun_read(int _fd, void *_buffer, ssize_t _buf_size);
ssize_t tun_write(int _fd, void *_buffer, ssize_t _buf_size);
