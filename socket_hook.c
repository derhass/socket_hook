#define _GNU_SOURCE
#include <dlfcn.h>	/* for RTLD_NEXT */
#include <pthread.h>	/* for mutextes */
#include <unistd.h>	/* for usleep(3) */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SH_SOCKET_DESC_SIZE	256

/***************************************************************************
 * helpers                                                                 *
 ***************************************************************************/

static void
set_errno(int value)
{
	errno=value;
}

static void
set_h_errno(int value)
{
	h_errno=value;
}

#if 0
static const char *
get_envs(const char *name, const char *def)
{
	const char *s=getenv(name);
	return (s)?s:def;
}
#endif

static int
get_envi(const char *name, int def)
{
	const char *s=getenv(name);
	int i;

	if (s) {
		i=(int)strtol(s,NULL,0);
	} else {
		i=def;
	}
	return i;
}

#ifdef SH_CONTEXT_TRACKING

static unsigned int
get_envui(const char *name, unsigned int def)
{
	const char *s=getenv(name);
	int i;

	if (s) {
		i=(unsigned)strtoul(s,NULL,0);
	} else {
		i=def;
	}
	return i;
}

#endif

static size_t
buf_printf(char *buf, size_t pos, size_t size, const char *fmt, ...)
{
	va_list args;
	size_t left=size-pos;
	int r;

	va_start(args, fmt);
	r=vsnprintf(buf+pos, left, fmt, args);
	va_end(args);

	if (r > 0) {
		size_t written=(size_t)r;
		pos += (written >= left)?left:written;
	}
	return pos;
}

static void
parse_name(char *buf, size_t size, const char *name_template, unsigned int ctx_num)
{
	struct timespec ts_now;
	int in_escape=0;
	size_t pos=0;
	char c;

	buf[--size]=0; /* resverve space for final NUL terminator */
	while ( (pos < size) && (c=*(name_template++)) ) {
		if (in_escape) {
			switch(c) {
				case '%':
					buf[pos++]=c;
					break;
				case 'c':
					pos=buf_printf(buf,pos,size,"%u",ctx_num);
					break;
				case 'p':
					pos=buf_printf(buf,pos,size,"%u",(unsigned)getpid());
					break;
				case 't':
					clock_gettime(CLOCK_REALTIME, &ts_now);
					pos=buf_printf(buf,pos,size,"%09lld.%ld",
							(long long)ts_now.tv_sec,
							ts_now.tv_nsec);
					break;
				default:
					pos=buf_printf(buf,pos,size,"%%%c",c);
			}
			in_escape=0;
		} else {
			switch(c) {
				case '%':
					in_escape=1;
					break;
				default:
					buf[pos++]=c;
			}
		}
	}
	buf[pos]=0;
}

static int
get_string_idx(const char *str, const char **modes, int default_value, int case_sensitive)
{
	int idx;

	if (!str ||!modes) {
		return default_value;
	}

	for (idx=0; modes[idx]; idx++) {
		int cmp=(case_sensitive)?strcmp(modes[idx],str):strcasecmp(modes[idx],str);
		if (!cmp) {
			return idx;
		}
	}
	return default_value;
}

/***************************************************************************
 * MESSAGE OUTPUT                                                          *
 ***************************************************************************/

typedef enum {
	SH_MSG_NONE=0,
	SH_MSG_ERROR,
	SH_MSG_WARNING,
	SH_MSG_INFO,
	SH_MSG_DEBUG,
	SH_MSG_DEBUG_INTERCEPTION
} SH_msglevel;

#ifdef NDEBUG
#define SH_MSG_LEVEL_DEFAULT SH_MSG_WARNING
#else
#define SH_MSG_LEVEL_DEFAULT SH_MSG_DEBUG_INTERCEPTION
#endif

#define SH_DEFAULT_OUTPUT_STREAM stderr

static void SH_verbose(int level, const char *fmt, ...)
{
	static int verbosity=-1;
	static FILE *output_stream=NULL;
	static int stream_initialized=0;
	va_list args;

	if (verbosity < 0) {
		verbosity=get_envi("SH_VERBOSE", SH_MSG_LEVEL_DEFAULT);
	}

	if (level > verbosity) {
		return;
	}

	if (!stream_initialized) {
		const char *file=getenv("SH_VERBOSE_FILE");
		if (file) {
			char buf[PATH_MAX];
			parse_name(buf, sizeof(buf), file, 0);
			output_stream=fopen(buf,"a+t");
		}
		if (!output_stream)
			output_stream=SH_DEFAULT_OUTPUT_STREAM;
		stream_initialized=1;
	}
	fprintf(output_stream,"SH: ");
	va_start(args, fmt);
	vfprintf(output_stream, fmt, args);
	va_end(args);
	fflush(output_stream);
}

/***************************************************************************
 * FUNCTION INTERCEPTOR LOGIC                                              *
 ***************************************************************************/

typedef void (*SH_fptr)();
typedef void * (*SH_resolve_func)(const char *);

/* mutex used during SH_dlsym_internal () */
static pthread_mutex_t SH_mutex=PTHREAD_MUTEX_INITIALIZER;

/* Mutex for the function pointers. We only guard the
 * if (ptr == NULL) ptr=...; part. The pointers will never
 * change after being set to a non-NULL value for the first time,
 * so it is safe to dereference them without locking */
static pthread_mutex_t SH_fptr_mutex=PTHREAD_MUTEX_INITIALIZER;

/* THIS IS AN EVIL HACK: we directly call _dl_sym() of the glibc */
extern void *_dl_sym(void *, const char *, void (*)() );

/* Wrapper function called in place of dlsym(), since we intercept dlsym().
 * We use this ONLY to get the original dlsym() itself, all other symbol
 * resolutions are done via that original function, then.
 */
static void *SH_dlsym_internal(void *handle, const char *name)
{
	void *ptr;

	/* ARGH: we are bypassing glibc's locking for dlsym(), so we
	 * must do this on our own */
	pthread_mutex_lock(&SH_mutex);

	/* Third argument is the address of the caller, (glibc uses stack
	 * unwinding internally to get this),  we just use the address of our
	 * wrapper function itself, which is wrong when this is called on
	 * behalf of the real application doing a dlsycm, but we do not
	 *  care... */
	ptr=_dl_sym(handle, name, (void (*)())SH_dlsym_internal);

	pthread_mutex_unlock(&SH_mutex);
	return ptr;
}

/* Wrapper funtcion to query the original dlsym() function avoiding
 * recursively calls to the interceptor dlsym() below */
static void *SH_dlsym_internal_next(const char *name)
{
	return SH_dlsym_internal(RTLD_NEXT, name);
}

/* return intercepted function pointer for a symbol */
static void *SH_get_interceptor(const char*, SH_resolve_func, const char *);

/* function pointers to call the real functions that we did intercept */
static void * (* volatile SH_dlsym)(void *, const char*)=NULL;
static void * (* volatile SH_dlvsym)(void *, const char*, const char *)=NULL;
static int (* volatile SH_socket)(int, int, int)=NULL;
static int (* volatile SH_connect)(int, const struct sockaddr*, socklen_t)=NULL;
static struct hostent * (* volatile SH_gethostbyname)(const char *)=NULL;
static struct hostent * (* volatile SH_gethostbyname2)(const char *, int)=NULL;
static struct hostent * (* volatile SH_gethostbyaddr)(const void *, socklen_t, int)=NULL;
static int (* volatile SH_gethostbyname_r)(const char *, struct hostent *, char *, size_t, struct hostent **, int *);
static int (* volatile SH_gethostbyname2_r)(const char *, int, struct hostent *, char *, size_t, struct hostent **, int *);
static int (* volatile SH_gethostbyaddr_r)(const void *, socklen_t, int, struct hostent *, char *, size_t, struct hostent **, int *);
static int (* volatile SH_getaddrinfo)(const char*, const char*, const struct addrinfo *, struct addrinfo **);
static int (* volatile SH_getaddrinfo_a)(int, struct gaicb *list[], int, struct sigevent *);

/* Resolve an unintercepted symbol via the original dlsym() */
static void *SH_dlsym_next(const char *name)
{
	return SH_dlsym(RTLD_NEXT, name);
}

/* helper macro: query the symbol pointer if it is NULL
 * handle the locking */
#define SH_GET_PTR(func) \
	pthread_mutex_lock(&SH_fptr_mutex); \
	if(SH_ ##func == NULL) \
		SH_ ##func = SH_dlsym_next(#func);\
	pthread_mutex_unlock(&SH_fptr_mutex)


/***************************************************************************
 * INTERCEPTED FUNCTIONS: libdl/libc                                       *
 ***************************************************************************/

/* intercept dlsym() itself */
extern void *
dlsym(void *handle, const char *name)
{
	void *interceptor;
	void *ptr;
	/* special case: we cannot use SH_GET_PTR as it relies on
	 * SH_dlsym() which we have to query using SH_dlsym_internal */
	pthread_mutex_lock(&SH_fptr_mutex); \
	if(SH_dlsym == NULL)
		SH_dlsym = SH_dlsym_internal_next("dlsym");
	pthread_mutex_unlock(&SH_fptr_mutex);
	interceptor=SH_get_interceptor(name, SH_dlsym_next, "dlsym");
	ptr=(interceptor)?interceptor:SH_dlsym(handle,name);
	SH_verbose(SH_MSG_DEBUG_INTERCEPTION,"dlsym(%p, %s) = %p%s\n",handle,name,ptr,
		interceptor?" [intercepted]":"");
	return ptr;
}

/* also intercept GNU specific dlvsym() */
extern void *
dlvsym(void *handle, const char *name, const char *version)
{
	void *interceptor;
	void *ptr;
	SH_GET_PTR(dlvsym); \
	interceptor=SH_get_interceptor(name, SH_dlsym_next, "dlsym");
	ptr=(interceptor)?interceptor:SH_dlvsym(handle,name,version);
	SH_verbose(SH_MSG_DEBUG_INTERCEPTION,"dlvsym(%p, %s, %s) = %p%s\n",handle,name,version,ptr,
		interceptor?" [intercepted]":"");
	return ptr;
}

/***************************************************************************
 * SOCKET ADDRESSES                                                        *
 ***************************************************************************/

static int validate_sockaddr(const struct sockaddr *addr, socklen_t addrlen)
{
	(void)addr;

	if (addrlen > sizeof(struct sockaddr_storage)) {
		SH_verbose(SH_MSG_WARNING, "got invalid socket address from application: addrlen %d > max addr len %d\n", (int)addrlen, (int)sizeof(struct sockaddr_storage));
		return -1;
	}
	switch (addr->sa_family)
	{
		case AF_INET:
			if (addrlen < offsetof(struct sockaddr_in,sin_zero)) {
				SH_verbose(SH_MSG_WARNING, "got invalid socket address from application: IPv4 addrlen %d < %d\n", (int)addrlen, (int)offsetof(struct sockaddr_in,sin_zero));
				return -1;
			}
			if (addrlen != sizeof(struct sockaddr_in)) {
				SH_verbose(SH_MSG_WARNING, "IPv4 addrlen %d !=  %d\n", (int)addrlen, (int)sizeof(struct sockaddr_in));
				return 1;
			}
			break;
		case AF_INET6:
			if (addrlen < offsetof(struct sockaddr_in6,sin6_scope_id)) {
				SH_verbose(SH_MSG_WARNING, "got invalid socket address from application: IPv6 addrlen %d < %d\n", (int)addrlen, (int)offsetof(struct sockaddr_in6,sin6_scope_id));
				return -1;
			}
			if (addrlen != sizeof(struct sockaddr_in6)) {
				SH_verbose(SH_MSG_WARNING, "IPv6 addrlen %d !=  %d\n", (int)addrlen, (int)sizeof(struct sockaddr_in6));
				return 1;
			}
			break;

	}
	return 0;
}


/* write human-readbale description of a sockaddr to buf, which must be
 * at least SH_SOCKET_DESC_SIZE bytes big, and returns buf */
static char *describe_sockaddr(char *buf, const struct sockaddr *addr, socklen_t addrlen)
{
	switch (addr->sa_family) {
		case AF_INET:
			{
				const struct sockaddr_in *a=(const struct sockaddr_in *)addr;
				snprintf(buf, SH_SOCKET_DESC_SIZE, "IPv4:%s:%u",
					inet_ntoa(a->sin_addr),ntohs(a->sin_port));
			}
			break;
		case AF_INET6:
			{
				const struct sockaddr_in6 *a=(const struct sockaddr_in6 *)addr;
				const char *b=(const char*)&a->sin6_addr;
				snprintf(buf, SH_SOCKET_DESC_SIZE, "IPv6:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%u",
					b[0],
					b[1],
					b[2],
					b[3],
					b[4],
					b[5],
					b[6],
					b[7],
					b[8],
					b[9],
					b[10],
					b[11],
					b[12],
					b[13],
					b[14],
					b[15],
					ntohs(a->sin6_port));
			}
			break;
		default:
			snprintf(buf, SH_SOCKET_DESC_SIZE, "family=%d len=%d", addr->sa_family,(int)addrlen);
	}
	return buf;
}

/***************************************************************************
 * SOCKET INTERCEPTION LOGIC                                               *
 ***************************************************************************/

/* the different interception modes */
typedef enum {
	SH_SOCKET_UNINITIALIZED=-1, /* only for internal use */
	/* real modes follow */
	SH_SOCKET_NONE=0,
	SH_SOCKET_LOCAL,
	SH_SOCKET_ALL
} SH_socket_mode;

static SH_socket_mode
get_socket_mode(void)
{
	static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
	static SH_socket_mode mode=SH_SOCKET_UNINITIALIZED;

	pthread_mutex_lock(&mutex);
	if (mode == SH_SOCKET_UNINITIALIZED) {
		static const char *modes[]={
			"none",
			"local",
			"all",
			NULL
		};
		const char *str = getenv("SH_SOCKET");
		mode=get_string_idx(str, modes, SH_SOCKET_ALL, 0);
	}
	pthread_mutex_unlock(&mutex);

	return mode;
}

static int
socket_intercept(int domain, int type, int protocol)
{
	int res;

	switch(get_socket_mode()) {
		case SH_SOCKET_NONE:
			SH_verbose(SH_MSG_INFO, "rejected socket(%d, %d, %d)\n", domain, type, protocol);
			set_errno(EACCES);
			return -1;
		case SH_SOCKET_LOCAL:
			if (domain != AF_UNIX && domain != AF_LOCAL) {
				SH_verbose(SH_MSG_INFO, "rejected socket(%d, %d, %d): non-local\n", domain, type, protocol);
				set_errno(EACCES);
				return -1;
			}
			break;
		case SH_SOCKET_ALL:
			(void)0;
			break;
		default:
			SH_verbose(SH_MSG_ERROR, "invalid SH_SOCKET mode %d\n", get_socket_mode());
	}

	res=SH_socket(domain, type, protocol);
	if (res < 0) {
		SH_verbose(SH_MSG_WARNING, "socket(%d, %d, %d) call failed with %d:%s\n", domain, type, protocol, errno, strerror(errno));
	}
	return res;
}

static int connect_intercept(int sockfd, const struct sockaddr *addr, socklen_t addrlen, char *buf)
{
	int res=SH_connect(sockfd, addr, addrlen);
	if (res < 0) {
		if (errno == EINPROGRESS) {
			SH_verbose(SH_MSG_DEBUG,"connect(%d, [%s]) in progress\n", 
				errno, describe_sockaddr(buf, addr, addrlen));
		} else {
			SH_verbose(SH_MSG_WARNING,"connect(%d, [%s]) call failed with %d:%s\n", 
				errno, describe_sockaddr(buf, addr, addrlen), strerror(errno));
		}
	}
	return res;
}

static struct hostent *gethostbyname_intercept(const char *name)
{
	struct hostent *res=SH_gethostbyname(name);
	if (!res) {
		SH_verbose(SH_MSG_WARNING,"gethostbyname(%s) call failed with %d:%s\n",
			name, h_errno, hstrerror(h_errno));
	}
	return res;
}

static int gethostbyname_r_intercept(const char *name,
		struct hostent *ret, char *buf, size_t buflen,
		struct hostent **result, int *h_errnop)
{
	int res=SH_gethostbyname_r(name, ret, buf, buflen, result, h_errnop);
	if (res < 0) {
		if (h_errnop) {
			SH_verbose(SH_MSG_WARNING,"gethostbyname_r(%s) call failed with %d:%s\n",
				name, *h_errnop, hstrerror(*h_errnop));
		} else {
			SH_verbose(SH_MSG_WARNING,"gethostbyname_r(%s) call failed\n",
				name);
		}
	}
	return res;
}

static struct hostent *gethostbyname2_intercept(const char *name, int af)
{
	struct hostent *res=SH_gethostbyname2(name, af);
	if (!res) {
		SH_verbose(SH_MSG_WARNING,"gethostbyname2(%s, %d) call failed with %d:%s\n",
			name, af, h_errno, hstrerror(h_errno));
	}
	return res;
}

static int gethostbyname2_r_intercept(const char *name, int af,
		struct hostent *ret, char *buf, size_t buflen,
		struct hostent **result, int *h_errnop)
{
	int res=SH_gethostbyname2_r(name, af, ret, buf, buflen, result, h_errnop);
	if (res < 0) {
		if (h_errnop) {
			SH_verbose(SH_MSG_WARNING,"gethostbyname_r(%s, %d) call failed with %d:%s\n",
				name, af, *h_errnop, hstrerror(*h_errnop));
		} else {
			SH_verbose(SH_MSG_WARNING,"gethostbyname_r(%s, %d) call failed\n",
				name, af);
		}
	}
	return res;
}

static struct hostent *gethostbyaddr_intercept(const void *addr, socklen_t len, int type)
{
	struct hostent *res=SH_gethostbyaddr(addr, len, type);
	if (!res) {
		SH_verbose(SH_MSG_WARNING,"gethostbyaddr([...], %d) call failed with %d:%s\n",
			type, h_errno, hstrerror(h_errno));
	}
	return res;
}

static int gethostbyaddr_r_intercept(const void *addr, socklen_t len, int type,
		struct hostent *ret, char *buf, size_t buflen,
		struct hostent **result, int *h_errnop)
{
	int res=SH_gethostbyaddr_r(addr, len, type, ret, buf, buflen, result, h_errnop);
	if (res < 0) {
		if (h_errnop) {
			SH_verbose(SH_MSG_WARNING,"gethostbyaddr_r([...], %d) call failed with %d:%s\n",
				type, *h_errnop, hstrerror(*h_errnop));
		} else {
			SH_verbose(SH_MSG_WARNING,"gethostbyaddr_r([...], %d) call failed\n",
				type);
		}
	}
	return res;
}

static int getaddrinfo_intercept(const char *node, const char *service,
		const struct addrinfo *hints, struct addrinfo **res)
{
	int result=SH_getaddrinfo(node, service, hints, res);
	if (result != 0) {
		SH_verbose(SH_MSG_WARNING,"getaddrinfo(%s, %s) failed with %d\n",
			node, service, result);
	}
	return result;
}

static int getaddrinfo_a_intercept(int mode, struct gaicb *list[], int nitems, struct sigevent *sevp)
{
	int result=SH_getaddrinfo_a(mode, list, nitems, sevp);
	if (result != 0) {
		SH_verbose(SH_MSG_WARNING,"getaddrinfo_a(%d, [...], %d) failed with %d\n",
			mode, nitems, result);
	}
	return result;
}

/***************************************************************************
 * INTERCEPTED FUNCTIONS: socket API                                       *
 ***************************************************************************/

/* Actually, our goal is to intercept glXSwapInterval[EXT|SGI]() etc. But
 * these are extension functions not required to be provided as external
 * symbols. However, some applications just likn them anyways, so we have
 * to handle the case were dlsym() or glXGetProcAddress[ARB]() is used to
 * query the function pointers, and have to intercept these as well.
 */

extern int socket(int domain, int type, int protocol)
{
	int result;

	SH_GET_PTR(socket);
	if (SH_socket == NULL) {
		SH_verbose(SH_MSG_ERROR,"socket() can't be reached!\n");
		set_errno(EINVAL);
		result=-1;
	} else {
		result=socket_intercept(domain, type, protocol);
	}
	SH_verbose(SH_MSG_DEBUG,"socket(%d,%d,%d) = %d\n",domain, type, protocol, result);
	return result;
}

extern int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int result=-1;
	char buf[SH_SOCKET_DESC_SIZE];

	if (validate_sockaddr(addr, addrlen) < 0) {
		SH_verbose(SH_MSG_DEBUG,"connect(%d,[...]) = %d due to invalid addr\n", sockfd, result);
		set_errno(EAFNOSUPPORT);
		return result;
	}

	SH_GET_PTR(connect);
	if (SH_connect == NULL) {
		SH_verbose(SH_MSG_ERROR,"connect() can't be reached!\n");
		set_errno(ENETUNREACH);
	} else {
		result=connect_intercept(sockfd, addr, addrlen, buf);
	}
	SH_verbose(SH_MSG_DEBUG,"connect(%d,[%s]) = %d\n", sockfd, describe_sockaddr(buf, addr, addrlen), result);
	return result;
}

extern struct hostent *gethostbyname(const char *name)
{
	struct hostent *result=NULL;

	SH_GET_PTR(gethostbyname);
	if (SH_gethostbyname == NULL) {
		SH_verbose(SH_MSG_ERROR,"gethosbyname() can't be reached!\n");
		set_h_errno(NO_RECOVERY);
	} else {
		result=gethostbyname_intercept(name);
	}
	SH_verbose(SH_MSG_DEBUG,"gethosybyname(%s) = %p\n", name, result);
	return result;
}

extern int gethostbyname_r(const char *name,
		struct hostent *ret, char *buf, size_t buflen,
		struct hostent **result, int *h_errnop)
{
	int res=-1;

	if (result) {
		*result=NULL;
	}
	SH_GET_PTR(gethostbyname_r);
	if (SH_gethostbyname_r == NULL) {
		SH_verbose(SH_MSG_ERROR,"gethosbyname_r() can't be reached!\n");
		if (h_errnop) {
			*h_errnop=NO_RECOVERY;
		}
	} else {
		res=gethostbyname_r_intercept(name, ret, buf, buflen, result, h_errnop);
	}
	SH_verbose(SH_MSG_DEBUG,"gethosybyname_r(%s) = %d\n", name, res);
	return res;
}

extern struct hostent *gethostbyname2(const char *name, int af)
{
	struct hostent *result=NULL;

	SH_GET_PTR(gethostbyname2);
	if (SH_gethostbyname2 == NULL) {
		SH_verbose(SH_MSG_ERROR,"gethosbyname2() can't be reached!\n");
		set_h_errno(NO_RECOVERY);
	} else {
		result=gethostbyname2_intercept(name, af);
	}
	SH_verbose(SH_MSG_DEBUG,"gethosybyname2(%s, %d) = %p\n", name, af, result);
	return result;
}

extern int gethostbyname2_r(const char *name, int af,
		struct hostent *ret, char *buf, size_t buflen,
		struct hostent **result, int *h_errnop)
{
	int res=-1;

	if (result) {
		*result=NULL;
	}
	SH_GET_PTR(gethostbyname2_r);
	if (SH_gethostbyname2_r == NULL) {
		SH_verbose(SH_MSG_ERROR,"gethosbyname2_r() can't be reached!\n");
		if (h_errnop) {
			*h_errnop=NO_RECOVERY;
		}
	} else {
		res=gethostbyname2_r_intercept(name, af, ret, buf, buflen, result, h_errnop);
	}
	SH_verbose(SH_MSG_DEBUG,"gethosybyname2_r(%s, %d) = %d\n", name, af, res);
	return res;
}

extern struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type)
{
	struct hostent *result=NULL;

	SH_GET_PTR(gethostbyaddr);
	if (SH_gethostbyaddr == NULL) {
		SH_verbose(SH_MSG_ERROR,"gethosbyaddr() can't be reached!\n");
		set_h_errno(NO_RECOVERY);
	} else {
		result=gethostbyaddr_intercept(addr, len, type);
	}
	SH_verbose(SH_MSG_DEBUG,"gethosybyaddr([...], %d) = %p\n", type, result);
	return result;
}

extern int gethostbyaddr_r(const void *addr, socklen_t len, int type,
		struct hostent *ret, char *buf, size_t buflen,
		struct hostent **result, int *h_errnop)
{
	int res=-1;

	if (result) {
		*result=NULL;
	}
	SH_GET_PTR(gethostbyaddr_r);
	if (SH_gethostbyaddr_r == NULL) {
		SH_verbose(SH_MSG_ERROR,"gethosbyaddr_r() can't be reached!\n");
		if (h_errnop) {
			*h_errnop=NO_RECOVERY;
		}
	} else {
		res=gethostbyaddr_r_intercept(addr, len, type, ret, buf, buflen, result, h_errnop);
	}
	SH_verbose(SH_MSG_DEBUG,"gethosybyaddr_r([...], %d) = %d\n", type, res);
	return res;
}


extern int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints, struct addrinfo **res)
{
	int result=EAI_FAIL;

	if (res) {
		*res=NULL;
	}
	SH_GET_PTR(getaddrinfo);
	if (SH_getaddrinfo == NULL) {
		SH_verbose(SH_MSG_ERROR,"getaddrinfo() can't be reached!\n");
	} else {
		result=getaddrinfo_intercept(node, service, hints, res);
	}
	SH_verbose(SH_MSG_DEBUG,"getaddrinfo(%s, %s) = %d\n", node, service, result);
	return result;
}

extern int getaddrinfo_a(int mode, struct gaicb *list[], int nitems, struct sigevent *sevp)
{
	int result=EAI_MEMORY;

	SH_GET_PTR(getaddrinfo_a);
	if (SH_getaddrinfo_a == NULL) {
		SH_verbose(SH_MSG_ERROR,"getaddrinfo_a() can't be reached!\n");
	} else {
		result=getaddrinfo_a_intercept(mode, list, nitems, sevp);
	}
	SH_verbose(SH_MSG_DEBUG,"getaddrinfo_a(%d, [...], %d) = %d\n", mode, nitems, result);
	return result;
}

/***************************************************************************
 * LIST OF INTERCEPTED FUNCTIONS                                           *
 ***************************************************************************/

/* return intercepted fuction pointer for "name", or NULL if
 * "name" is not to be intercepted. If function is intercepted,
 * use query to resolve the original function pointer and store
 * it in the SH_"name" static pointer. That way, we use the same
 * function the original application were using without the interceptor.
 * The interceptor functions will fall back to using SH_dlsym() if the
 * name resolution here did fail for some reason.
 */
static void* SH_get_interceptor(const char *name, SH_resolve_func query,
				const char *query_name )
{
#define SH_INTERCEPT(func) \
       	if (!strcmp(#func, name)) {\
		pthread_mutex_lock(&SH_fptr_mutex); \
		if ( (SH_ ##func == NULL) && query) { \
			SH_ ##func = query(#func); \
			SH_verbose(SH_MSG_DEBUG,"queried internal %s via %s: %p\n", \
				name,query_name, SH_ ##func); \
		} \
		pthread_mutex_unlock(&SH_fptr_mutex); \
		return func; \
	}

	SH_INTERCEPT(dlsym);
	SH_INTERCEPT(dlvsym);
	SH_INTERCEPT(socket);
	SH_INTERCEPT(connect);
	SH_INTERCEPT(gethostbyname);
	SH_INTERCEPT(gethostbyname_r);
	SH_INTERCEPT(gethostbyname2);
	SH_INTERCEPT(gethostbyname2_r);
	SH_INTERCEPT(gethostbyaddr);
	SH_INTERCEPT(gethostbyaddr_r);
	SH_INTERCEPT(getaddrinfo);
	SH_INTERCEPT(getaddrinfo_a);
	return NULL;
}

