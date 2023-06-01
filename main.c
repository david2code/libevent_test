#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <event.h>
#include <signal.h>
#include <time.h>

struct event_base *base;
struct event ev;
struct event *ev2;
struct timeval tv;
struct timeval tv2;

void timer_cb(int fd, short event, void *arg)
{
    printf("timer_cb, %p\n", arg);
    event_add(ev2, &tv);

    struct timeval tv3;
    event_base_gettimeofday_cached(arg, &tv3);
    printf("time, %ld\n", tv3.tv_sec);
    //event_base_loopbreak(arg);
}

void cb_func(evutil_socket_t fd, short what, void *arg)
{
    const char *data = arg;
    printf("Got an event on socket %d:%s%s%s%s [%s]\n",
            (int)fd,
            (what & EV_TIMEOUT) ? " timeout" : "",
            (what & EV_READ) ? " read" : "",
            (what & EV_WRITE) ? " write" : "",
            (what & EV_SIGNAL) ? " signal" : "",
            data);
}

void ev_timer_test()
{
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    //event_set(&ev, -1, 0, timer_cb, base);
    //event_base_set(base, &ev);
    ev2 = event_new(base, -1, 0, timer_cb, base);
    event_add(ev2, &tv);
}

void ev_timer_test2()
{
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    ev2 = evtimer_new(base, timer_cb, base);
    evtimer_add(ev2, &tv);
}

void ev_test()
{
    struct event *ev1, *ev2;
    struct timeval five_seconds = {5, 0};
    
    ev1 = event_new(base, -1, EV_TIMEOUT | EV_READ | EV_PERSIST, cb_func, (char*)"Reading event");
    ev2 = event_new(base, -1, EV_WRITE | EV_PERSIST, cb_func, (char*)"Writing event");

    event_add(ev1, &five_seconds);
    event_add(ev2, NULL);
}

static int n_calls = 0;
void self_cbarg_func(evutil_socket_t fd, short what, void *arg)
{
    struct event *me = arg;

    printf("%s called %d times so far.\n", __FUNCTION__, ++n_calls);
    if (n_calls > 10)
        event_del(me);
}

void self_cbarg_test()
{
    struct timeval one_sec = {1, 0};
    struct event *ev;
    ev = event_new(base, -1, EV_PERSIST, self_cbarg_func, event_self_cbarg());
    event_add(ev, &one_sec);
}


void signal_function(evutil_socket_t fd, short what, void *arg)
{
    printf("%s signal %d happen.\n", __FUNCTION__, fd);
}

void evsignal_test()
{
    struct event *sig_event;
    //hup_event = evsignal_new(base, SIGHUP | SIGTERM |SIGINT | SIGSEGV, signal_function, NULL);
    sig_event = evsignal_new(base, SIGINT, signal_function, NULL);
    if (0 != evsignal_add(sig_event, NULL)) {
        printf("sigint event_add failed!");
    }
}


void ev_active_cb(evutil_socket_t fd, short what, void *arg) 
{
    struct event *me = (struct event *)arg;
    event_active(me, EV_WRITE, 0);
}

void ev_active_test()
{
    struct event *ev = event_new(base, -1, EV_PERSIST | EV_READ, ev_active_cb, event_self_cbarg()); 
    event_add(ev, NULL);
    event_active(ev, EV_WRITE, 0);
}

void timer_func_test()
{
    struct timeval tv1, tv2, tv3;

    tv1.tv_sec = 5; tv1.tv_usec = 500 * 1000;
    evutil_gettimeofday(&tv2, NULL);
    evutil_timeradd(&tv1, &tv2, &tv3);

    if (evutil_timercmp(&tv1, &tv1, ==))
        puts("5.5 sec = 5.5 sec");
    if (evutil_timercmp(&tv3, &tv2, >=))
        puts("the future is after the presend.");
    if (evutil_timercmp(&tv1, &tv2, <))
        puts("it is no longer the past.");
}

#include <ctype.h>
void readcb(struct bufferevent *bev, void *arg)
{
    char tmp[128];
    size_t n;
    int i;
    while(1) {
        n = bufferevent_read(bev, tmp, sizeof(tmp));
        if (n <= 0)
            break;
        for (i = 0; i < n; ++i)
            tmp[i] = toupper(tmp[i]);
        bufferevent_write(bev, tmp, n);
    }
}

struct total_processed {
    size_t n;
};
struct total_processed total = {0};
void count_megabytes_cb(struct evbuffer *buffer, const struct evbuffer_cb_info *info, void *arg)
{
    struct total_processed *tp = arg;
    size_t old_n = tp->n;
    int megabytes, i;
    tp->n += info->n_deleted;
    megabytes = ((tp->n) >> 10) - (old_n >> 10);
    //printf("%s called, tp-> %lu, old_n %lu, megabytes: %d\n", __FUNCTION__, tp->n, old_n, megabytes);
    for (i = 0; i < megabytes; ++i)
        putc('.', stdout);
}
struct count {
    unsigned long last_fib[2];
};
void write_cb_fibonacci(struct bufferevent *bev, void *ctx)
{
    struct count *c = ctx;
    struct evbuffer *tmp = evbuffer_new();
    struct evbuffer_cb_entry *cb_entry = evbuffer_add_cb(tmp, count_megabytes_cb, &total);
    //evbuffer_cb_clear_flags(tmp, cb_entry, EVBUFFER_CB_ENABLED);
    while(evbuffer_get_length(tmp) < 1024) {
        unsigned long next = c->last_fib[0] + c->last_fib[1];
        c->last_fib[0] = c->last_fib[1];
        c->last_fib[1] = next;
        evbuffer_add_printf(tmp, "%lu ", next);
    }

    //printf("write fibonacci\n");
    bufferevent_write_buffer(bev, tmp);
    evbuffer_free(tmp);
}

#define HUGE_RESOURCE_SIZE (1024 * 1024)
struct huge_resource {
    int reference_count;
    char data[HUGE_RESOURCE_SIZE];
};
struct huge_resource *new_resource(void) {
    struct huge_resource *hr = malloc(sizeof(struct huge_resource));
    hr->reference_count = 1;
    memset(hr->data, 0x41, sizeof(hr->data));
    return hr;
}
void free_resource(struct huge_resource *hr) {
    --hr->reference_count;
    if (hr->reference_count == 0)
        free(hr);
    printf("reference_count: %d\n", hr->reference_count);
}
static void cleanup(const void *data, size_t len, void *arg) {
    free_resource(arg);
}
void write_cb_huge_resource(struct bufferevent *bev, void *arg)
{
    struct huge_resource *hr = (struct huge_resource *)arg;
    struct evbuffer *tmp = evbuffer_new();
    hr->reference_count++;
    printf("reference_count: %d\n", hr->reference_count);
    evbuffer_add_reference(tmp, hr->data, HUGE_RESOURCE_SIZE, cleanup, hr);
    bufferevent_write_buffer(bev, tmp);
    evbuffer_free(tmp);
}

void eventcb(struct bufferevent *bev, short events, void *ptr)
{
    if (events & BEV_EVENT_CONNECTED) {
        puts("connected\n");
    } else if (events & BEV_EVENT_ERROR) {
        puts("connect error\n");
    }
}

int bufferevent_test()
{
    struct bufferevent *bev;
    struct sockaddr_in sin;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0x7f000001);
    sin.sin_port = htons(8080);

    bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

#if 0
    struct count fib;
    fib.last_fib[0] = 0;
    fib.last_fib[1] = 1;
    bufferevent_setcb(bev, readcb, write_cb_fibonacci, eventcb, &fib);
#else
    struct huge_resource *hr = new_resource();
    bufferevent_setcb(bev, readcb, write_cb_huge_resource, eventcb, hr);
#endif
    bufferevent_enable(bev, EV_READ | EV_WRITE);

    if (bufferevent_socket_connect(bev, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        bufferevent_free(bev);
        return -1;
    }

    return 0;
}

void readcb2(struct bufferevent *bev, void *arg)
{
    char buf[1024];
    int n;
    struct evbuffer *input = bufferevent_get_input(bev);
    printf("length:%lu\n", evbuffer_get_length(input));
    printf("contiguous length:%lu\n", evbuffer_get_contiguous_space(input));

    struct evbuffer_iovec v[2];
    n = evbuffer_peek(input, -1, NULL, v, 2); 
    printf("peek start %d\n", n);
    for (int i = 0; i < n; ++i) {
        fwrite(v[i].iov_base, 1, v[i].iov_len, stderr);
    }
    printf("peek end\n");

    n = evbuffer_peek(input, 4096, NULL, NULL, 0);
    printf("peek start %d\n", n);
    struct evbuffer_iovec *iov = malloc(sizeof(struct evbuffer_iovec) * n);
    n = evbuffer_peek(input, 4096, NULL, iov, n);
    size_t written = 0;
    for (int i = 0; i < n; ++i) {
        size_t len = iov[i].iov_len;
        if (written + len > 4096)
            len = 4096 - written;
        int r = fwrite(iov[i].iov_base, 1, len, stderr);
        if (r <= 0)
            break;
        written += len;
    }
    free(iov);
    printf("peek end\n");


    printf("peek start %d\n", n);
    struct evbuffer_ptr ptr;
    char *search_str = "Bad";
    ptr = evbuffer_search(input, search_str, strlen(search_str), NULL);
    if (ptr.pos == -1) {
        printf("search not found\n");
        return;
    }
    if (evbuffer_ptr_set(input, &ptr, strlen(search_str), EVBUFFER_PTR_ADD) < 0)
        return;
    written = 0;
    while(written < 16) {
        if (evbuffer_peek(input, -1, &ptr, v, 1) < 1)
            break;
        fwrite(v[0].iov_base, 1, v[0].iov_len, stderr);
        written += v[0].iov_len;
        if (evbuffer_ptr_set(input, &ptr, v[0].iov_len, EVBUFFER_PTR_ADD) < 0)
            break;
    }

    printf("peek end\n");

    while((n = evbuffer_remove(input, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, n, stdout);
    }
}

void eventcb2(struct bufferevent *bev, short events, void *ptr)
{
    if (events & BEV_EVENT_CONNECTED) {
        printf("Connect okay.\n");
    } else if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        struct event_base *base = ptr;
        if (events & BEV_EVENT_ERROR) {
            int err = bufferevent_socket_get_dns_error(bev);
            if (err)
                printf("DNS error: %s\n", evutil_gai_strerror(err));
        }
        printf("Closing\n");
        bufferevent_free(bev);
    }
}

#include <event2/dns.h>
int bufferevent_test2()
{
    struct evdns_base *dns_base;
    struct bufferevent *bev;
    dns_base = evdns_base_new(base, 1);
    bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, readcb2, NULL, eventcb2, base);
    //bufferevent_setwatermark(bev, EV_READ, 18, 0);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    evbuffer_add_printf(bufferevent_get_output(bev), "GET %s\r\n", "/");
    bufferevent_socket_connect_hostname(bev, dns_base, AF_UNSPEC, "www.baidu.com", 80);
}

#if 1
//test evconnlistener

#include <event2/listener.h>
static void echo_read_cb(struct bufferevent *bev, void *ctx)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    char buf[200];
    
    size_t len = evbuffer_get_length(input);
    if (len < 4)
        return;
    len = bufferevent_read(bev, buf, sizeof(buf));
    if (len > 0)
    {
        buf[len] = 0;
        printf("len: %ld, [%s]\n", len, buf);
    }
    //evbuffer_add_buffer(output, input);
}


static void echo_event_cb(struct bufferevent *bev, short events, void *ctx)
{
    if (events & BEV_EVENT_ERROR)
        perror("Error from bufferevent\n");

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
        bufferevent_free(bev);
    }

    if (events & BEV_EVENT_TIMEOUT)
    {
        printf("events: %hu\n", events);
        if (events & BEV_EVENT_READING)
        {
            printf("reading timeout\n");
        }
        else if (events & BEV_EVENT_WRITING)
        {
            printf("writing timeout\n");
        }
        bufferevent_free(bev);
    }
}
const char *MESSAGE = "HELLO, bitch!\r\n";
static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

    struct sockaddr_in *client_addr = (struct sockaddr_in *)address;

    printf("ip: %u, port: %hu\n", client_addr->sin_addr.s_addr, client_addr->sin_port);

    bufferevent_setcb(bev, echo_read_cb, NULL, echo_event_cb, NULL);
    bufferevent_settimeout(bev, 10, 10);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    
	bufferevent_write(bev, MESSAGE, strlen(MESSAGE));
}

static void accept_error_cb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *base = evconnlistener_get_base(listener);

    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Got an error %d (%s) on the listener. shutting down.\n",
        err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
}

int evconnlistener_test()
{
    struct event_base *base;
    struct evconnlistener *listener;
    struct sockaddr_in sin;

    int port = 8889;
    base = event_base_new();

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0);
    sin.sin_port = htons(port);

    listener = evconnlistener_new_bind(base, accept_conn_cb, NULL, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (struct sockaddr *)&sin, sizeof(sin));

    if (!listener)
    {
        perror("couldn't create listener");
        return 1;
    }

    evconnlistener_set_error_cb(listener, accept_error_cb);

    event_base_dispatch(base);
    return 0;
}

#endif

int main()
{
    printf("%s event_size:%lu\n", event_get_version(), event_get_struct_event_size());
    timer_func_test();

    evconnlistener_test();


    //struct event_base *base = event_init();
    //base = event_base_new();
    struct event_config *cfg;
    cfg = event_config_new();
    //run at most 16 callbacks before checking for other events
    event_config_set_max_dispatch_interval(cfg, NULL, 16, 0);
    event_config_avoid_method(cfg, "select");
    event_config_require_features(cfg, EV_FEATURE_ET);
    base = event_base_new_with_config(cfg);
    event_base_priority_init(base, 3);
    event_config_free(cfg);

    const char **methods = event_get_supported_methods();
    for (int i = 0; methods[i] != NULL; i++) {
        printf("   %s\n", methods[i]);
    }
    printf("Using libevent with backend method: %s.\n", event_base_get_method(base));
    printf("Using libevent with priority: %d.\n", event_base_get_npriorities(base));

    //ev_timer_test();
    //ev_timer_test2();
    //ev_test();
    //self_cbarg_test();
    //evsignal_test();
    //ev_active_test();
    bufferevent_test();
    //bufferevent_test2();

    tv2.tv_sec = 20;
    event_base_loopexit(base, &tv2);
    event_base_dispatch(base);
    printf("tick\n");

    event_free(ev2);
    event_base_free(base);
    libevent_global_shutdown();
    return 0;
}