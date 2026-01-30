#ifndef R_SIGNAL_H
#define R_SIGNAL_H

#include <r_types.h>
#if R2__UNIX__
#include <signal.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef bool (*RSignalCallback)(void *user, const char *name, int code);

/* Returns atoi(str) if signal with `str` name not found. */
R_API int r_signal_from_string(const char *str);

/* Return NULL if signal with `code` not found. */
R_API const char* r_signal_tostring(int code);
R_API void r_signal_foreach(RSignalCallback cb, void *user);
R_API const char *r_signal_to_human(int signum);

// XXX this function should be portable, not-unix specific
#if R2__UNIX__
R_API void r_signal_sigmask(int how, const sigset_t *newmask, sigset_t *oldmask);
#endif

#ifdef __cplusplus
}
#endif

#endif //  R_SIGNAL_H
