#ifndef __ALTLOG_H__
#define __ALTLOG_H__ 1
#ifdef WITH_ALTLOG

int altlog_writexfer(const int upload,
                     const char * const filename,
                     const off_t size,
                     const double duration);

int altlog_write_w3c_header(void);
#endif
#endif
