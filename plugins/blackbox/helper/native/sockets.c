/*
 * Every process's TCP/UDP sockets and the network interfaces' byte and packet counters,
 * read straight from macOS (libproc; the routing socket's NET_RT_IFLIST2 for the interfaces'
 * 64-bit counters): no program started, microseconds per call.
 *
 * WHY C and not Rust FFI structs: struct socket_fdinfo (sys/proc_info.h) is a deep union whose
 * layout only the system headers define correctly; compiling against them keeps the layout exact
 * on every macOS. The functions below flatten what Rust needs into two plain records.
 *
 * Bounded: at most `cap` records; at most `fd_cap` descriptors looked at per process. A process
 * this user may not inspect (another user's, root's) is skipped — nettop still covers those.
 */
#include <libproc.h>
#include <sys/proc_info.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/route.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int32_t pid;
    uint8_t family;     /* 4 or 6 */
    uint8_t protocol;   /* IPPROTO_TCP (6) or IPPROTO_UDP (17) */
    int16_t tcp_state;  /* TSI_S_* for TCP, -1 for UDP */
    uint16_t local_port;
    uint16_t remote_port;
    uint8_t local_addr[16];
    uint8_t remote_addr[16];
} bb_socket;

typedef struct {
    char name[16];
    uint8_t loopback;
    uint8_t up;
    uint8_t _pad[6];
    /* 64-bit (struct if_data64): getifaddrs' if_data counters are 32-bit and wrapped at 4 GiB. */
    uint64_t bytes_in;
    uint64_t bytes_out;
    uint64_t packets_in;
    uint64_t packets_out;
} bb_iface;

static void copy_addr(uint8_t *out, int ipv4, const struct in_sockinfo *in, int foreign) {
    memset(out, 0, 16);
    if (ipv4) {
        const struct in_addr *a = foreign ? &in->insi_faddr.ina_46.i46a_addr4 : &in->insi_laddr.ina_46.i46a_addr4;
        memcpy(out, a, 4);
    } else {
        const struct in6_addr *a = foreign ? &in->insi_faddr.ina_6 : &in->insi_laddr.ina_6;
        memcpy(out, a, 16);
    }
}

/* The sockets of every process this user may inspect. Answers how many records were written. */
int bb_list_sockets(bb_socket *out, int cap, int fd_cap) {
    int pid_bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (pid_bytes <= 0 || cap <= 0) return 0;
    int pid_cap = pid_bytes / (int)sizeof(pid_t) + 64;
    pid_t *pids = calloc((size_t)pid_cap, sizeof(pid_t));
    struct proc_fdinfo *fds = calloc((size_t)fd_cap, sizeof(struct proc_fdinfo));
    if (!pids || !fds) { free(pids); free(fds); return 0; }
    int npids = proc_listpids(PROC_ALL_PIDS, 0, pids, pid_cap * (int)sizeof(pid_t)) / (int)sizeof(pid_t);
    int count = 0;
    for (int p = 0; p < npids && count < cap; p++) {
        pid_t pid = pids[p];
        if (pid <= 0) continue;
        int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, fd_cap * (int)sizeof(struct proc_fdinfo));
        if (fd_bytes <= 0) continue;   /* not ours to inspect, or gone */
        int nfds = fd_bytes / (int)sizeof(struct proc_fdinfo);
        for (int f = 0; f < nfds && count < cap; f++) {
            if (fds[f].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
            struct socket_fdinfo si;
            if (proc_pidfdinfo(pid, fds[f].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si)) < (int)sizeof(si)) continue;
            int kind = si.psi.soi_kind;
            if (kind != SOCKINFO_TCP && kind != SOCKINFO_IN) continue;
            int family = si.psi.soi_family;
            if (family != AF_INET && family != AF_INET6) continue;
            const struct in_sockinfo *in = kind == SOCKINFO_TCP ? &si.psi.soi_proto.pri_tcp.tcpsi_ini : &si.psi.soi_proto.pri_in;
            int ipv4 = (in->insi_vflag & INI_IPV4) != 0;
            bb_socket *s = &out[count++];
            s->pid = pid;
            s->family = ipv4 ? 4 : 6;
            s->protocol = kind == SOCKINFO_TCP ? IPPROTO_TCP : IPPROTO_UDP;
            s->tcp_state = kind == SOCKINFO_TCP ? (int16_t)si.psi.soi_proto.pri_tcp.tcpsi_state : -1;
            s->local_port = ntohs((uint16_t)in->insi_lport);
            s->remote_port = ntohs((uint16_t)in->insi_fport);
            copy_addr(s->local_addr, ipv4, in, 0);
            copy_addr(s->remote_addr, ipv4, in, 1);
        }
    }
    free(pids);
    free(fds);
    return count;
}

/* Every interface's 64-bit byte and packet counters (one RTM_IFINFO2 message per interface).
 * Answers how many records were written. */
int bb_list_ifaces(bb_iface *out, int cap) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0};
    size_t length = 0;
    if (cap <= 0 || sysctl(mib, 6, NULL, &length, NULL, 0) != 0 || length == 0) return 0;
    length += length / 4;   /* room for an interface that appears between the two calls */
    char *buffer = malloc(length);
    if (!buffer) return 0;
    if (sysctl(mib, 6, buffer, &length, NULL, 0) != 0) { free(buffer); return 0; }
    int count = 0;
    for (char *next = buffer; next + sizeof(struct if_msghdr) <= buffer + length && count < cap;) {
        const struct if_msghdr *message = (const struct if_msghdr *)next;
        if (message->ifm_msglen == 0) break;
        next += message->ifm_msglen;
        if (message->ifm_type != RTM_IFINFO2 || message->ifm_msglen < sizeof(struct if_msghdr2)) continue;
        const struct if_msghdr2 *info = (const struct if_msghdr2 *)message;
        bb_iface *f = &out[count];
        memset(f, 0, sizeof(*f));
        if (!if_indextoname(info->ifm_index, f->name)) continue;   /* IFNAMSIZ == sizeof(f->name) */
        f->name[sizeof(f->name) - 1] = 0;
        f->loopback = (info->ifm_flags & IFF_LOOPBACK) != 0;
        f->up = (info->ifm_flags & IFF_UP) != 0;
        f->bytes_in = info->ifm_data.ifi_ibytes;
        f->bytes_out = info->ifm_data.ifi_obytes;
        f->packets_in = info->ifm_data.ifi_ipackets;
        f->packets_out = info->ifm_data.ifi_opackets;
        count++;
    }
    free(buffer);
    return count;
}

/* Layout checks for the Rust side (it declares the same records). */
size_t bb_socket_size(void) { return sizeof(bb_socket); }
size_t bb_iface_size(void) { return sizeof(bb_iface); }
