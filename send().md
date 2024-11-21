net/socket.c

```c title=send()
SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,

unsigned int, flags)

{

return __sys_sendto(fd, buff, len, flags, NULL, 0);

}
```

```c title=sendto()
SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,

unsigned int, flags, struct sockaddr __user *, addr,

int, addr_len)

{

return __sys_sendto(fd, buff, len, flags, addr, addr_len);

}
```

```c title=__sys_sendto()
/*

* Send a datagram to a given address. We move the address into kernel

* space and check the user space data area is readable before invoking

* the protocol.

*/

int __sys_sendto(int fd, void __user *buff, size_t len, unsigned int flags,

struct sockaddr __user *addr, int addr_len)

{

struct socket *sock;

struct sockaddr_storage address;

int err;

struct msghdr msg;

int fput_needed;

  

err = import_ubuf(ITER_SOURCE, buff, len, &msg.msg_iter);

if (unlikely(err))

return err;

sock = sockfd_lookup_light(fd, &err, &fput_needed);

if (!sock)

goto out;

  

msg.msg_name = NULL;

msg.msg_control = NULL;

msg.msg_controllen = 0;

msg.msg_namelen = 0;

msg.msg_ubuf = NULL;

if (addr) {

err = move_addr_to_kernel(addr, addr_len, &address);

if (err < 0)

goto out_put;

msg.msg_name = (struct sockaddr *)&address;

msg.msg_namelen = addr_len;

}

flags &= ~MSG_INTERNAL_SENDMSG_FLAGS;

if (sock->file->f_flags & O_NONBLOCK)

flags |= MSG_DONTWAIT;

msg.msg_flags = flags;

err = __sock_sendmsg(sock, &msg);

  

out_put:

fput_light(sock->file, fput_needed);

out:

return err;

}
```

```c title=kernel_sendmsg()
/**

* kernel_sendmsg - send a message through @sock (kernel-space)

* @sock: socket

* @msg: message header

* @vec: kernel vec

* @num: vec array length

* @size: total message data size

*

* Builds the message data with @vec and sends it through @sock.

* Returns the number of bytes sent, or an error code.

*/

  

int kernel_sendmsg(struct socket *sock, struct msghdr *msg,

struct kvec *vec, size_t num, size_t size)

{

iov_iter_kvec(&msg->msg_iter, ITER_SOURCE, vec, num, size);

return sock_sendmsg(sock, msg);

}

EXPORT_SYMBOL(kernel_sendmsg);
```

```c title=sock_sendmsg
/**

* sock_sendmsg - send a message through @sock

* @sock: socket

* @msg: message to send

*

* Sends @msg through @sock, passing through LSM.

* Returns the number of bytes sent, or an error code.

*/

int sock_sendmsg(struct socket *sock, struct msghdr *msg)

{

struct sockaddr_storage *save_addr = (struct sockaddr_storage *)msg->msg_name;

struct sockaddr_storage address;

int save_len = msg->msg_namelen;

int ret;

  

if (msg->msg_name) {

memcpy(&address, msg->msg_name, msg->msg_namelen);

msg->msg_name = &address;

}

  

ret = __sock_sendmsg(sock, msg);

msg->msg_name = save_addr;

msg->msg_namelen = save_len;

  

return ret;

}

EXPORT_SYMBOL(sock_sendmsg);
```

```c title=__sock_sendmsg()
static int __sock_sendmsg(struct socket *sock, struct msghdr *msg)

{

int err = security_socket_sendmsg(sock, msg,

msg_data_left(msg));

  

return err ?: sock_sendmsg_nosec(sock, msg);

}
```

```c title=sock_sendmsg_nosec()
static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)

{

int ret = INDIRECT_CALL_INET(READ_ONCE(sock->ops)->sendmsg, inet6_sendmsg,

inet_sendmsg, sock, msg,

msg_data_left(msg));

BUG_ON(ret == -EIOCBQUEUED);

  

if (trace_sock_send_length_enabled())

call_trace_sock_send_length(sock->sk, ret, 0);

return ret;

}
```

```c title=inet_sendmsg()
int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)

{

struct sock *sk = sock->sk;

  

if (unlikely(inet_send_prepare(sk)))

return -EAGAIN;

  

return INDIRECT_CALL_2(sk->sk_prot->sendmsg, tcp_sendmsg, udp_sendmsg,

sk, msg, size);

}

EXPORT_SYMBOL(inet_sendmsg);
```

net/ipv4/tcp.c

```c title=tcp_sendmsg()
int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)

{

int ret;

  

lock_sock(sk);

ret = tcp_sendmsg_locked(sk, msg, size);

release_sock(sk);

  

return ret;

}

EXPORT_SYMBOL(tcp_sendmsg);
```

```c title=tcp_sendmsg_locked()
int tcp_sendmsg_locked(struct sock *sk, struct msghdr *msg, size_t size)

{

struct tcp_sock *tp = tcp_sk(sk);

struct ubuf_info *uarg = NULL;

struct sk_buff *skb;

struct sockcm_cookie sockc;

int flags, err, copied = 0;

int mss_now = 0, size_goal, copied_syn = 0;

int process_backlog = 0;

int zc = 0;

long timeo;

  

flags = msg->msg_flags;

  

if ((flags & MSG_ZEROCOPY) && size) {

if (msg->msg_ubuf) {

uarg = msg->msg_ubuf;

if (sk->sk_route_caps & NETIF_F_SG)

zc = MSG_ZEROCOPY;

} else if (sock_flag(sk, SOCK_ZEROCOPY)) {

skb = tcp_write_queue_tail(sk);

uarg = msg_zerocopy_realloc(sk, size, skb_zcopy(skb));

if (!uarg) {

err = -ENOBUFS;

goto out_err;

}

if (sk->sk_route_caps & NETIF_F_SG)

zc = MSG_ZEROCOPY;

else

uarg_to_msgzc(uarg)->zerocopy = 0;

}

} else if (unlikely(msg->msg_flags & MSG_SPLICE_PAGES) && size) {

if (sk->sk_route_caps & NETIF_F_SG)

zc = MSG_SPLICE_PAGES;

}

  

if (unlikely(flags & MSG_FASTOPEN ||

inet_test_bit(DEFER_CONNECT, sk)) &&

!tp->repair) {

err = tcp_sendmsg_fastopen(sk, msg, &copied_syn, size, uarg);

if (err == -EINPROGRESS && copied_syn > 0)

goto out;

else if (err)

goto out_err;

}

  

timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

  

tcp_rate_check_app_limited(sk); /* is sending application-limited? */

  

/* Wait for a connection to finish. One exception is TCP Fast Open

* (passive side) where data is allowed to be sent before a connection

* is fully established.

*/

if (((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)) &&

!tcp_passive_fastopen(sk)) {

err = sk_stream_wait_connect(sk, &timeo);

if (err != 0)

goto do_error;

}

  

if (unlikely(tp->repair)) {

if (tp->repair_queue == TCP_RECV_QUEUE) {

copied = tcp_send_rcvq(sk, msg, size);

goto out_nopush;

}

  

err = -EINVAL;

if (tp->repair_queue == TCP_NO_QUEUE)

goto out_err;

  

/* 'common' sending to sendq */

}

  

sockcm_init(&sockc, sk);

if (msg->msg_controllen) {

err = sock_cmsg_send(sk, msg, &sockc);

if (unlikely(err)) {

err = -EINVAL;

goto out_err;

}

}

  

/* This should be in poll */

sk_clear_bit(SOCKWQ_ASYNC_NOSPACE, sk);

  

/* Ok commence sending. */

copied = 0;

  

restart:

mss_now = tcp_send_mss(sk, &size_goal, flags);

  

err = -EPIPE;

if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))

goto do_error;

  

while (msg_data_left(msg)) {

ssize_t copy = 0;

  

skb = tcp_write_queue_tail(sk);

if (skb)

copy = size_goal - skb->len;

  

if (copy <= 0 || !tcp_skb_can_collapse_to(skb)) {

bool first_skb;

  

new_segment:

if (!sk_stream_memory_free(sk))

goto wait_for_space;

  

if (unlikely(process_backlog >= 16)) {

process_backlog = 0;

if (sk_flush_backlog(sk))

goto restart;

}

first_skb = tcp_rtx_and_write_queues_empty(sk);

skb = tcp_stream_alloc_skb(sk, sk->sk_allocation,

first_skb);

if (!skb)

goto wait_for_space;

  

process_backlog++;

  

tcp_skb_entail(sk, skb);

copy = size_goal;

  

/* All packets are restored as if they have

* already been sent. skb_mstamp_ns isn't set to

* avoid wrong rtt estimation.

*/

if (tp->repair)

TCP_SKB_CB(skb)->sacked |= TCPCB_REPAIRED;

}

  

/* Try to append data to the end of skb. */

if (copy > msg_data_left(msg))

copy = msg_data_left(msg);

  

if (zc == 0) {

bool merge = true;

int i = skb_shinfo(skb)->nr_frags;

struct page_frag *pfrag = sk_page_frag(sk);

  

if (!sk_page_frag_refill(sk, pfrag))

goto wait_for_space;

  

if (!skb_can_coalesce(skb, i, pfrag->page,

pfrag->offset)) {

if (i >= READ_ONCE(sysctl_max_skb_frags)) {

tcp_mark_push(tp, skb);

goto new_segment;

}

merge = false;

}

  

copy = min_t(int, copy, pfrag->size - pfrag->offset);

  

if (unlikely(skb_zcopy_pure(skb) || skb_zcopy_managed(skb))) {

if (tcp_downgrade_zcopy_pure(sk, skb))

goto wait_for_space;

skb_zcopy_downgrade_managed(skb);

}

  

copy = tcp_wmem_schedule(sk, copy);

if (!copy)

goto wait_for_space;

  

err = skb_copy_to_page_nocache(sk, &msg->msg_iter, skb,

pfrag->page,

pfrag->offset,

copy);

if (err)

goto do_error;

  

/* Update the skb. */

if (merge) {

skb_frag_size_add(&skb_shinfo(skb)->frags[i - 1], copy);

} else {

skb_fill_page_desc(skb, i, pfrag->page,

pfrag->offset, copy);

page_ref_inc(pfrag->page);

}

pfrag->offset += copy;

} else if (zc == MSG_ZEROCOPY) {

/* First append to a fragless skb builds initial

* pure zerocopy skb

*/

if (!skb->len)

skb_shinfo(skb)->flags |= SKBFL_PURE_ZEROCOPY;

  

if (!skb_zcopy_pure(skb)) {

copy = tcp_wmem_schedule(sk, copy);

if (!copy)

goto wait_for_space;

}

  

err = skb_zerocopy_iter_stream(sk, skb, msg, copy, uarg);

if (err == -EMSGSIZE || err == -EEXIST) {

tcp_mark_push(tp, skb);

goto new_segment;

}

if (err < 0)

goto do_error;

copy = err;

} else if (zc == MSG_SPLICE_PAGES) {

/* Splice in data if we can; copy if we can't. */

if (tcp_downgrade_zcopy_pure(sk, skb))

goto wait_for_space;

copy = tcp_wmem_schedule(sk, copy);

if (!copy)

goto wait_for_space;

  

err = skb_splice_from_iter(skb, &msg->msg_iter, copy,

sk->sk_allocation);

if (err < 0) {

if (err == -EMSGSIZE) {

tcp_mark_push(tp, skb);

goto new_segment;

}

goto do_error;

}

copy = err;

  

if (!(flags & MSG_NO_SHARED_FRAGS))

skb_shinfo(skb)->flags |= SKBFL_SHARED_FRAG;

  

sk_wmem_queued_add(sk, copy);

sk_mem_charge(sk, copy);

}

  

if (!copied)

TCP_SKB_CB(skb)->tcp_flags &= ~TCPHDR_PSH;

  

WRITE_ONCE(tp->write_seq, tp->write_seq + copy);

TCP_SKB_CB(skb)->end_seq += copy;

tcp_skb_pcount_set(skb, 0);

  

copied += copy;

if (!msg_data_left(msg)) {

if (unlikely(flags & MSG_EOR))

TCP_SKB_CB(skb)->eor = 1;

goto out;

}

  

if (skb->len < size_goal || (flags & MSG_OOB) || unlikely(tp->repair))

continue;

  

if (forced_push(tp)) {

tcp_mark_push(tp, skb);

__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_PUSH);

} else if (skb == tcp_send_head(sk))

tcp_push_one(sk, mss_now);

continue;

  

wait_for_space:

set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);

tcp_remove_empty_skb(sk);

if (copied)

tcp_push(sk, flags & ~MSG_MORE, mss_now,

TCP_NAGLE_PUSH, size_goal);

  

err = sk_stream_wait_memory(sk, &timeo);

if (err != 0)

goto do_error;

  

mss_now = tcp_send_mss(sk, &size_goal, flags);

}

  

out:

if (copied) {

tcp_tx_timestamp(sk, sockc.tsflags);

tcp_push(sk, flags, mss_now, tp->nonagle, size_goal);

}

out_nopush:

/* msg->msg_ubuf is pinned by the caller so we don't take extra refs */

if (uarg && !msg->msg_ubuf)

net_zcopy_put(uarg);

return copied + copied_syn;

  

do_error:

tcp_remove_empty_skb(sk);

  

if (copied + copied_syn)

goto out;

out_err:

/* msg->msg_ubuf is pinned by the caller so we don't take extra refs */

if (uarg && !msg->msg_ubuf)

net_zcopy_put_abort(uarg, true);

err = sk_stream_error(sk, flags, err);

/* make sure we wake any epoll edge trigger waiter */

if (unlikely(tcp_rtx_and_write_queues_empty(sk) && err == -EAGAIN)) {

sk->sk_write_space(sk);

tcp_chrono_stop(sk, TCP_CHRONO_SNDBUF_LIMITED);

}

return err;

}

EXPORT_SYMBOL_GPL(tcp_sendmsg_locked);

  

int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)

{

int ret;

  

lock_sock(sk);

ret = tcp_sendmsg_locked(sk, msg, size);

release_sock(sk);

  

return ret;

}

EXPORT_SYMBOL(tcp_sendmsg);
```

```c title=tcp_push()
void tcp_push(struct sock *sk, int flags, int mss_now,

int nonagle, int size_goal)

{

struct tcp_sock *tp = tcp_sk(sk);

struct sk_buff *skb;

  

skb = tcp_write_queue_tail(sk);

if (!skb)

return;

if (!(flags & MSG_MORE) || forced_push(tp))

tcp_mark_push(tp, skb);

  

tcp_mark_urg(tp, flags);

  

if (tcp_should_autocork(sk, skb, size_goal)) {

  

/* avoid atomic op if TSQ_THROTTLED bit is already set */

if (!test_bit(TSQ_THROTTLED, &sk->sk_tsq_flags)) {

NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPAUTOCORKING);

set_bit(TSQ_THROTTLED, &sk->sk_tsq_flags);

smp_mb__after_atomic();

}

/* It is possible TX completion already happened

* before we set TSQ_THROTTLED.

*/

if (refcount_read(&sk->sk_wmem_alloc) > skb->truesize)

return;

}

  

if (flags & MSG_MORE)

nonagle = TCP_NAGLE_CORK;

  

__tcp_push_pending_frames(sk, mss_now, nonagle);

}
```

/net/ipv4/tcp_output.c

```c title=__tcp_push_pending_frames
/* Push out any pending frames which were held back due to

* TCP_CORK or attempt at coalescing tiny packets.

* The socket must be locked by the caller.

*/

void __tcp_push_pending_frames(struct sock *sk, unsigned int cur_mss,

int nonagle)

{

/* If we are closed, the bytes will have to remain here.

* In time closedown will finish, we empty the write queue and

* all will be happy.

*/

if (unlikely(sk->sk_state == TCP_CLOSE))

return;

  

if (tcp_write_xmit(sk, cur_mss, nonagle, 0,

sk_gfp_mask(sk, GFP_ATOMIC)))

tcp_check_probe_timer(sk);

}
```

```c title=tcp_write_xmit()
/* This routine writes packets to the network. It advances the

* send_head. This happens as incoming acks open up the remote

* window for us.

*

* LARGESEND note: !tcp_urg_mode is overkill, only frames between

* snd_up-64k-mss .. snd_up cannot be large. However, taking into

* account rare use of URG, this is not a big flaw.

*

* Send at most one packet when push_one > 0. Temporarily ignore

* cwnd limit to force at most one packet out when push_one == 2.

  

* Returns true, if no segments are in flight and we have queued segments,

* but cannot send anything now because of SWS or another problem.

*/

static bool tcp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle,

int push_one, gfp_t gfp)

{

struct tcp_sock *tp = tcp_sk(sk);

struct sk_buff *skb;

unsigned int tso_segs, sent_pkts;

int cwnd_quota;

int result;

bool is_cwnd_limited = false, is_rwnd_limited = false;

u32 max_segs;

  

sent_pkts = 0;

  

tcp_mstamp_refresh(tp);

if (!push_one) {

/* Do MTU probing. */

result = tcp_mtu_probe(sk);

if (!result) {

return false;

} else if (result > 0) {

sent_pkts = 1;

}

}

  

max_segs = tcp_tso_segs(sk, mss_now);

while ((skb = tcp_send_head(sk))) {

unsigned int limit;

  

if (unlikely(tp->repair) && tp->repair_queue == TCP_SEND_QUEUE) {

/* "skb_mstamp_ns" is used as a start point for the retransmit timer */

tp->tcp_wstamp_ns = tp->tcp_clock_cache;

skb_set_delivery_time(skb, tp->tcp_wstamp_ns, true);

list_move_tail(&skb->tcp_tsorted_anchor, &tp->tsorted_sent_queue);

tcp_init_tso_segs(skb, mss_now);

goto repair; /* Skip network transmission */

}

  

if (tcp_pacing_check(sk))

break;

  

tso_segs = tcp_init_tso_segs(skb, mss_now);

BUG_ON(!tso_segs);

  

cwnd_quota = tcp_cwnd_test(tp, skb);

if (!cwnd_quota) {

if (push_one == 2)

/* Force out a loss probe pkt. */

cwnd_quota = 1;

else

break;

}

  

if (unlikely(!tcp_snd_wnd_test(tp, skb, mss_now))) {

is_rwnd_limited = true;

break;

}

  

if (tso_segs == 1) {

if (unlikely(!tcp_nagle_test(tp, skb, mss_now,

(tcp_skb_is_last(sk, skb) ?

nonagle : TCP_NAGLE_PUSH))))

break;

} else {

if (!push_one &&

tcp_tso_should_defer(sk, skb, &is_cwnd_limited,

&is_rwnd_limited, max_segs))

break;

}

  

limit = mss_now;

if (tso_segs > 1 && !tcp_urg_mode(tp))

limit = tcp_mss_split_point(sk, skb, mss_now,

min_t(unsigned int,

cwnd_quota,

max_segs),

nonagle);

  

if (skb->len > limit &&

unlikely(tso_fragment(sk, skb, limit, mss_now, gfp)))

break;

  

if (tcp_small_queue_check(sk, skb, 0))

break;

  

/* Argh, we hit an empty skb(), presumably a thread

* is sleeping in sendmsg()/sk_stream_wait_memory().

* We do not want to send a pure-ack packet and have

* a strange looking rtx queue with empty packet(s).

*/

if (TCP_SKB_CB(skb)->end_seq == TCP_SKB_CB(skb)->seq)

break;

  

if (unlikely(tcp_transmit_skb(sk, skb, 1, gfp)))

break;

  

repair:

/* Advance the send_head. This one is sent out.

* This call will increment packets_out.

*/

tcp_event_new_data_sent(sk, skb);

  

tcp_minshall_update(tp, mss_now, skb);

sent_pkts += tcp_skb_pcount(skb);

  

if (push_one)

break;

}

  

if (is_rwnd_limited)

tcp_chrono_start(sk, TCP_CHRONO_RWND_LIMITED);

else

tcp_chrono_stop(sk, TCP_CHRONO_RWND_LIMITED);

  

is_cwnd_limited |= (tcp_packets_in_flight(tp) >= tcp_snd_cwnd(tp));

if (likely(sent_pkts || is_cwnd_limited))

tcp_cwnd_validate(sk, is_cwnd_limited);

  

if (likely(sent_pkts)) {

if (tcp_in_cwnd_reduction(sk))

tp->prr_out += sent_pkts;

  

/* Send one loss probe per tail loss episode. */

if (push_one != 2)

tcp_schedule_loss_probe(sk, false);

return false;

}

return !tp->packets_out && !tcp_write_queue_empty(sk);

}
```

```c title=tcp_transmit_skb()
static int tcp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it,

gfp_t gfp_mask)

{

return __tcp_transmit_skb(sk, skb, clone_it, gfp_mask,

tcp_sk(sk)->rcv_nxt);

}
```

```c title=__tcp_transmit_skb()
/* This routine actually transmits TCP packets queued in by

* tcp_do_sendmsg(). This is used by both the initial

* transmission and possible later retransmissions.

* All SKB's seen here are completely headerless. It is our

* job to build the TCP header, and pass the packet down to

* IP so it can do the same plus pass the packet off to the

* device.

*

* We are working here with either a clone of the original

* SKB, or a fresh unique copy made by the retransmit engine.

*/

static int __tcp_transmit_skb(struct sock *sk, struct sk_buff *skb,

int clone_it, gfp_t gfp_mask, u32 rcv_nxt)

{

const struct inet_connection_sock *icsk = inet_csk(sk);

struct inet_sock *inet;

struct tcp_sock *tp;

struct tcp_skb_cb *tcb;

struct tcp_out_options opts;

unsigned int tcp_options_size, tcp_header_size;

struct sk_buff *oskb = NULL;

struct tcp_key key;

struct tcphdr *th;

u64 prior_wstamp;

int err;

  

BUG_ON(!skb || !tcp_skb_pcount(skb));

tp = tcp_sk(sk);

prior_wstamp = tp->tcp_wstamp_ns;

tp->tcp_wstamp_ns = max(tp->tcp_wstamp_ns, tp->tcp_clock_cache);

skb_set_delivery_time(skb, tp->tcp_wstamp_ns, true);

if (clone_it) {

oskb = skb;

  

tcp_skb_tsorted_save(oskb) {

if (unlikely(skb_cloned(oskb)))

skb = pskb_copy(oskb, gfp_mask);

else

skb = skb_clone(oskb, gfp_mask);

} tcp_skb_tsorted_restore(oskb);

  

if (unlikely(!skb))

return -ENOBUFS;

/* retransmit skbs might have a non zero value in skb->dev

* because skb->dev is aliased with skb->rbnode.rb_left

*/

skb->dev = NULL;

}

  

inet = inet_sk(sk);

tcb = TCP_SKB_CB(skb);

memset(&opts, 0, sizeof(opts));

  

tcp_get_current_key(sk, &key);

if (unlikely(tcb->tcp_flags & TCPHDR_SYN)) {

tcp_options_size = tcp_syn_options(sk, skb, &opts, &key);

} else {

tcp_options_size = tcp_established_options(sk, skb, &opts, &key);

/* Force a PSH flag on all (GSO) packets to expedite GRO flush

* at receiver : This slightly improve GRO performance.

* Note that we do not force the PSH flag for non GSO packets,

* because they might be sent under high congestion events,

* and in this case it is better to delay the delivery of 1-MSS

* packets and thus the corresponding ACK packet that would

* release the following packet.

*/

if (tcp_skb_pcount(skb) > 1)

tcb->tcp_flags |= TCPHDR_PSH;

}

tcp_header_size = tcp_options_size + sizeof(struct tcphdr);

  

/* We set skb->ooo_okay to one if this packet can select

* a different TX queue than prior packets of this flow,

* to avoid self inflicted reorders.

* The 'other' queue decision is based on current cpu number

* if XPS is enabled, or sk->sk_txhash otherwise.

* We can switch to another (and better) queue if:

* 1) No packet with payload is in qdisc/device queues.

* Delays in TX completion can defeat the test

* even if packets were already sent.

* 2) Or rtx queue is empty.

* This mitigates above case if ACK packets for

* all prior packets were already processed.

*/

skb->ooo_okay = sk_wmem_alloc_get(sk) < SKB_TRUESIZE(1) ||

tcp_rtx_queue_empty(sk);

  

/* If we had to use memory reserve to allocate this skb,

* this might cause drops if packet is looped back :

* Other socket might not have SOCK_MEMALLOC.

* Packets not looped back do not care about pfmemalloc.

*/

skb->pfmemalloc = 0;

  

skb_push(skb, tcp_header_size);

skb_reset_transport_header(skb);

  

skb_orphan(skb);

skb->sk = sk;

skb->destructor = skb_is_tcp_pure_ack(skb) ? __sock_wfree : tcp_wfree;

refcount_add(skb->truesize, &sk->sk_wmem_alloc);

  

skb_set_dst_pending_confirm(skb, READ_ONCE(sk->sk_dst_pending_confirm));

  

/* Build TCP header and checksum it. */

th = (struct tcphdr *)skb->data;

th->source = inet->inet_sport;

th->dest = inet->inet_dport;

th->seq = htonl(tcb->seq);

th->ack_seq = htonl(rcv_nxt);

*(((__be16 *)th) + 6) = htons(((tcp_header_size >> 2) << 12) |

tcb->tcp_flags);

  

th->check = 0;

th->urg_ptr = 0;

  

/* The urg_mode check is necessary during a below snd_una win probe */

if (unlikely(tcp_urg_mode(tp) && before(tcb->seq, tp->snd_up))) {

if (before(tp->snd_up, tcb->seq + 0x10000)) {

th->urg_ptr = htons(tp->snd_up - tcb->seq);

th->urg = 1;

} else if (after(tcb->seq + 0xFFFF, tp->snd_nxt)) {

th->urg_ptr = htons(0xFFFF);

th->urg = 1;

}

}

  

skb_shinfo(skb)->gso_type = sk->sk_gso_type;

if (likely(!(tcb->tcp_flags & TCPHDR_SYN))) {

th->window = htons(tcp_select_window(sk));

tcp_ecn_send(sk, skb, th, tcp_header_size);

} else {

/* RFC1323: The window in SYN & SYN/ACK segments

* is never scaled.

*/

th->window = htons(min(tp->rcv_wnd, 65535U));

}

  

tcp_options_write(th, tp, NULL, &opts, &key);

  

if (tcp_key_is_md5(&key)) {

#ifdef CONFIG_TCP_MD5SIG

/* Calculate the MD5 hash, as we have all we need now */

sk_gso_disable(sk);

tp->af_specific->calc_md5_hash(opts.hash_location,

key.md5_key, sk, skb);

#endif

} else if (tcp_key_is_ao(&key)) {

int err;

  

err = tcp_ao_transmit_skb(sk, skb, key.ao_key, th,

opts.hash_location);

if (err) {

kfree_skb_reason(skb, SKB_DROP_REASON_NOT_SPECIFIED);

return -ENOMEM;

}

}

  

/* BPF prog is the last one writing header option */

bpf_skops_write_hdr_opt(sk, skb, NULL, NULL, 0, &opts);

  

INDIRECT_CALL_INET(icsk->icsk_af_ops->send_check,

tcp_v6_send_check, tcp_v4_send_check,

sk, skb);

  

if (likely(tcb->tcp_flags & TCPHDR_ACK))

tcp_event_ack_sent(sk, rcv_nxt);

  

if (skb->len != tcp_header_size) {

tcp_event_data_sent(tp, sk);

tp->data_segs_out += tcp_skb_pcount(skb);

tp->bytes_sent += skb->len - tcp_header_size;

}

  

if (after(tcb->end_seq, tp->snd_nxt) || tcb->seq == tcb->end_seq)

TCP_ADD_STATS(sock_net(sk), TCP_MIB_OUTSEGS,

tcp_skb_pcount(skb));

  

tp->segs_out += tcp_skb_pcount(skb);

skb_set_hash_from_sk(skb, sk);

/* OK, its time to fill skb_shinfo(skb)->gso_{segs|size} */

skb_shinfo(skb)->gso_segs = tcp_skb_pcount(skb);

skb_shinfo(skb)->gso_size = tcp_skb_mss(skb);

  

/* Leave earliest departure time in skb->tstamp (skb->skb_mstamp_ns) */

  

/* Cleanup our debris for IP stacks */

memset(skb->cb, 0, max(sizeof(struct inet_skb_parm),

sizeof(struct inet6_skb_parm)));

  

tcp_add_tx_delay(skb, tp);

  

err = INDIRECT_CALL_INET(icsk->icsk_af_ops->queue_xmit,

inet6_csk_xmit, ip_queue_xmit,

sk, skb, &inet->cork.fl);

  

if (unlikely(err > 0)) {

tcp_enter_cwr(sk);

err = net_xmit_eval(err);

}

if (!err && oskb) {

tcp_update_skb_after_send(sk, oskb, prior_wstamp);

tcp_rate_skb_sent(sk, oskb);

}

return err;

}
```

/net/ipv4/ip_output.c

```c title=ip_queue_xmit()
int ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl)

{

return __ip_queue_xmit(sk, skb, fl, READ_ONCE(inet_sk(sk)->tos));

}

EXPORT_SYMBOL(ip_queue_xmit);
```

```c title=__ip_queue_xmit()
/* Note: skb->sk can be different from sk, in case of tunnels */

int __ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct flowi *fl,

__u8 tos)

{

struct inet_sock *inet = inet_sk(sk);

struct net *net = sock_net(sk);

struct ip_options_rcu *inet_opt;

struct flowi4 *fl4;

struct rtable *rt;

struct iphdr *iph;

int res;

  

/* Skip all of this if the packet is already routed,

* f.e. by something like SCTP.

*/

rcu_read_lock();

inet_opt = rcu_dereference(inet->inet_opt);

fl4 = &fl->u.ip4;

rt = skb_rtable(skb);

if (rt)

goto packet_routed;

  

/* Make sure we can route this packet. */

rt = (struct rtable *)__sk_dst_check(sk, 0);

if (!rt) {

__be32 daddr;

  

/* Use correct destination address if we have options. */

daddr = inet->inet_daddr;

if (inet_opt && inet_opt->opt.srr)

daddr = inet_opt->opt.faddr;

  

/* If this fails, retransmit mechanism of transport layer will

* keep trying until route appears or the connection times

* itself out.

*/

rt = ip_route_output_ports(net, fl4, sk,

daddr, inet->inet_saddr,

inet->inet_dport,

inet->inet_sport,

sk->sk_protocol,

RT_TOS(tos),

sk->sk_bound_dev_if);

if (IS_ERR(rt))

goto no_route;

sk_setup_caps(sk, &rt->dst);

}

skb_dst_set_noref(skb, &rt->dst);

  

packet_routed:

if (inet_opt && inet_opt->opt.is_strictroute && rt->rt_uses_gateway)

goto no_route;

  

/* OK, we know where to send it, allocate and build IP header. */

skb_push(skb, sizeof(struct iphdr) + (inet_opt ? inet_opt->opt.optlen : 0));

skb_reset_network_header(skb);

iph = ip_hdr(skb);

*((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (tos & 0xff));

if (ip_dont_fragment(sk, &rt->dst) && !skb->ignore_df)

iph->frag_off = htons(IP_DF);

else

iph->frag_off = 0;

iph->ttl = ip_select_ttl(inet, &rt->dst);

iph->protocol = sk->sk_protocol;

ip_copy_addrs(iph, fl4);

  

/* Transport layer set skb->h.foo itself. */

  

if (inet_opt && inet_opt->opt.optlen) {

iph->ihl += inet_opt->opt.optlen >> 2;

ip_options_build(skb, &inet_opt->opt, inet->inet_daddr, rt);

}

  

ip_select_ident_segs(net, skb, sk,

skb_shinfo(skb)->gso_segs ?: 1);

  

/* TODO : should we use skb->sk here instead of sk ? */

skb->priority = READ_ONCE(sk->sk_priority);

skb->mark = READ_ONCE(sk->sk_mark);

  

res = ip_local_out(net, sk, skb);

rcu_read_unlock();

return res;

  

no_route:

rcu_read_unlock();

IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);

kfree_skb_reason(skb, SKB_DROP_REASON_IP_OUTNOROUTES);

return -EHOSTUNREACH;

}

EXPORT_SYMBOL(__ip_queue_xmit);
```

```c title=dev_queue_xmit
ddd
```



/net/core/dev.c/

```c title=dev_queue_xmit
/**

* __dev_queue_xmit() - transmit a buffer

* @skb: buffer to transmit

* @sb_dev: suboordinate device used for L2 forwarding offload

*

* Queue a buffer for transmission to a network device. The caller must

* have set the device and priority and built the buffer before calling

* this function. The function can be called from an interrupt.

*

* When calling this method, interrupts MUST be enabled. This is because

* the BH enable code must have IRQs enabled so that it will not deadlock.

*

* Regardless of the return value, the skb is consumed, so it is currently

* difficult to retry a send to this method. (You can bump the ref count

* before sending to hold a reference for retry if you are careful.)

*

* Return:

* * 0 - buffer successfully transmitted

* * positive qdisc return code - NET_XMIT_DROP etc.

* * negative errno - other errors

*/

int __dev_queue_xmit(struct sk_buff *skb, struct net_device *sb_dev)

{

struct net_device *dev = skb->dev;

struct netdev_queue *txq = NULL;

struct Qdisc *q;

int rc = -ENOMEM;

bool again = false;

  

skb_reset_mac_header(skb);

skb_assert_len(skb);

  

if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_SCHED_TSTAMP))

__skb_tstamp_tx(skb, NULL, NULL, skb->sk, SCM_TSTAMP_SCHED);

  

/* Disable soft irqs for various locks below. Also

* stops preemption for RCU.

*/

rcu_read_lock_bh();

  

skb_update_prio(skb);

  

qdisc_pkt_len_init(skb);

tcx_set_ingress(skb, false);

#ifdef CONFIG_NET_EGRESS

if (static_branch_unlikely(&egress_needed_key)) {

if (nf_hook_egress_active()) {

skb = nf_hook_egress(skb, &rc, dev);

if (!skb)

goto out;

}

  

netdev_xmit_skip_txqueue(false);

  

nf_skip_egress(skb, true);

skb = sch_handle_egress(skb, &rc, dev);

if (!skb)

goto out;

nf_skip_egress(skb, false);

  

if (netdev_xmit_txqueue_skipped())

txq = netdev_tx_queue_mapping(dev, skb);

}

#endif

/* If device/qdisc don't need skb->dst, release it right now while

* its hot in this cpu cache.

*/

if (dev->priv_flags & IFF_XMIT_DST_RELEASE)

skb_dst_drop(skb);

else

skb_dst_force(skb);

  

if (!txq)

txq = netdev_core_pick_tx(dev, skb, sb_dev);

  

q = rcu_dereference_bh(txq->qdisc);

  

trace_net_dev_queue(skb);

if (q->enqueue) {

rc = __dev_xmit_skb(skb, q, dev, txq);

goto out;

}

  

/* The device has no queue. Common case for software devices:

* loopback, all the sorts of tunnels...

  

* Really, it is unlikely that netif_tx_lock protection is necessary

* here. (f.e. loopback and IP tunnels are clean ignoring statistics

* counters.)

* However, it is possible, that they rely on protection

* made by us here.

  

* Check this and shot the lock. It is not prone from deadlocks.

*Either shot noqueue qdisc, it is even simpler 8)

*/

if (dev->flags & IFF_UP) {

int cpu = smp_processor_id(); /* ok because BHs are off */

  

/* Other cpus might concurrently change txq->xmit_lock_owner

* to -1 or to their cpu id, but not to our id.

*/

if (READ_ONCE(txq->xmit_lock_owner) != cpu) {

if (dev_xmit_recursion())

goto recursion_alert;

  

skb = validate_xmit_skb(skb, dev, &again);

if (!skb)

goto out;

  

HARD_TX_LOCK(dev, txq, cpu);

  

if (!netif_xmit_stopped(txq)) {

dev_xmit_recursion_inc();

skb = dev_hard_start_xmit(skb, dev, txq, &rc);

dev_xmit_recursion_dec();

if (dev_xmit_complete(rc)) {

HARD_TX_UNLOCK(dev, txq);

goto out;

}

}

HARD_TX_UNLOCK(dev, txq);

net_crit_ratelimited("Virtual device %s asks to queue packet!\n",

dev->name);

} else {

/* Recursion is detected! It is possible,

* unfortunately

*/

recursion_alert:

net_crit_ratelimited("Dead loop on virtual device %s, fix it urgently!\n",

dev->name);

}

}

  

rc = -ENETDOWN;

rcu_read_unlock_bh();

  

dev_core_stats_tx_dropped_inc(dev);

kfree_skb_list(skb);

return rc;

out:

rcu_read_unlock_bh();

return rc;

}

EXPORT_SYMBOL(__dev_queue_xmit);
```






/drivers/net/ethernet/intel/ice/ice_txrx.c

```c title=ice_start_xmit()
/**

* ice_start_xmit - Selects the correct VSI and Tx queue to send buffer

* @skb: send buffer

* @netdev: network interface device structure

*

* Returns NETDEV_TX_OK if sent, else an error code

*/

netdev_tx_t ice_start_xmit(struct sk_buff *skb, struct net_device *netdev)

{

struct ice_netdev_priv *np = netdev_priv(netdev);

struct ice_vsi *vsi = np->vsi;

struct ice_tx_ring *tx_ring;

  

tx_ring = vsi->tx_rings[skb->queue_mapping];

  

/* hardware can't handle really short frames, hardware padding works

* beyond this point

*/

if (skb_put_padto(skb, ICE_MIN_TX_LEN))

return NETDEV_TX_OK;

  

return ice_xmit_frame_ring(skb, tx_ring);

}
```


```c title=ice_xmit_frame_ring()
/**

* ice_xmit_frame_ring - Sends buffer on Tx ring

* @skb: send buffer

* @tx_ring: ring to send buffer on

*

* Returns NETDEV_TX_OK if sent, else an error code

*/

static netdev_tx_t

ice_xmit_frame_ring(struct sk_buff *skb, struct ice_tx_ring *tx_ring)

{

struct ice_tx_offload_params offload = { 0 };

struct ice_vsi *vsi = tx_ring->vsi;

struct ice_tx_buf *first;

struct ethhdr *eth;

unsigned int count;

int tso, csum;

  

ice_trace(xmit_frame_ring, tx_ring, skb);

  

if (unlikely(ipv6_hopopt_jumbo_remove(skb)))

goto out_drop;

  

count = ice_xmit_desc_count(skb);

if (ice_chk_linearize(skb, count)) {

if (__skb_linearize(skb))

goto out_drop;

count = ice_txd_use_count(skb->len);

tx_ring->ring_stats->tx_stats.tx_linearize++;

}

  

/* need: 1 descriptor per page * PAGE_SIZE/ICE_MAX_DATA_PER_TXD,

* + 1 desc for skb_head_len/ICE_MAX_DATA_PER_TXD,

* + 4 desc gap to avoid the cache line where head is,

* + 1 desc for context descriptor,

* otherwise try next time

*/

if (ice_maybe_stop_tx(tx_ring, count + ICE_DESCS_PER_CACHE_LINE +

ICE_DESCS_FOR_CTX_DESC)) {

tx_ring->ring_stats->tx_stats.tx_busy++;

return NETDEV_TX_BUSY;

}

  

/* prefetch for bql data which is infrequently used */

netdev_txq_bql_enqueue_prefetchw(txring_txq(tx_ring));

  

offload.tx_ring = tx_ring;

  

/* record the location of the first descriptor for this packet */

first = &tx_ring->tx_buf[tx_ring->next_to_use];

first->skb = skb;

first->type = ICE_TX_BUF_SKB;

first->bytecount = max_t(unsigned int, skb->len, ETH_ZLEN);

first->gso_segs = 1;

first->tx_flags = 0;

  

/* prepare the VLAN tagging flags for Tx */

ice_tx_prepare_vlan_flags(tx_ring, first);

if (first->tx_flags & ICE_TX_FLAGS_HW_OUTER_SINGLE_VLAN) {

offload.cd_qw1 |= (u64)(ICE_TX_DESC_DTYPE_CTX |

(ICE_TX_CTX_DESC_IL2TAG2 <<

ICE_TXD_CTX_QW1_CMD_S));

offload.cd_l2tag2 = first->vid;

}

  

/* set up TSO offload */

tso = ice_tso(first, &offload);

if (tso < 0)

goto out_drop;

  

/* always set up Tx checksum offload */

csum = ice_tx_csum(first, &offload);

if (csum < 0)

goto out_drop;

  

/* allow CONTROL frames egress from main VSI if FW LLDP disabled */

eth = (struct ethhdr *)skb_mac_header(skb);

if (unlikely((skb->priority == TC_PRIO_CONTROL ||

eth->h_proto == htons(ETH_P_LLDP)) &&

vsi->type == ICE_VSI_PF &&

vsi->port_info->qos_cfg.is_sw_lldp))

offload.cd_qw1 |= (u64)(ICE_TX_DESC_DTYPE_CTX |

ICE_TX_CTX_DESC_SWTCH_UPLINK <<

ICE_TXD_CTX_QW1_CMD_S);

  

ice_tstamp(tx_ring, skb, first, &offload);

if (ice_is_switchdev_running(vsi->back))

ice_eswitch_set_target_vsi(skb, &offload);

  

if (offload.cd_qw1 & ICE_TX_DESC_DTYPE_CTX) {

struct ice_tx_ctx_desc *cdesc;

u16 i = tx_ring->next_to_use;

  

/* grab the next descriptor */

cdesc = ICE_TX_CTX_DESC(tx_ring, i);

i++;

tx_ring->next_to_use = (i < tx_ring->count) ? i : 0;

  

/* setup context descriptor */

cdesc->tunneling_params = cpu_to_le32(offload.cd_tunnel_params);

cdesc->l2tag2 = cpu_to_le16(offload.cd_l2tag2);

cdesc->rsvd = cpu_to_le16(0);

cdesc->qw1 = cpu_to_le64(offload.cd_qw1);

}

  

ice_tx_map(tx_ring, first, &offload);

return NETDEV_TX_OK;

  

out_drop:

ice_trace(xmit_frame_ring_drop, tx_ring, skb);

dev_kfree_skb_any(skb);

return NETDEV_TX_OK;

}
```



```c title=ice_tx_map()
/**

* ice_tx_map - Build the Tx descriptor

* @tx_ring: ring to send buffer on

* @first: first buffer info buffer to use

* @off: pointer to struct that holds offload parameters

*

* This function loops over the skb data pointed to by *first

* and gets a physical address for each memory location and programs

* it and the length into the transmit descriptor.

*/

static void

ice_tx_map(struct ice_tx_ring *tx_ring, struct ice_tx_buf *first,

struct ice_tx_offload_params *off)

{

u64 td_offset, td_tag, td_cmd;

u16 i = tx_ring->next_to_use;

unsigned int data_len, size;

struct ice_tx_desc *tx_desc;

struct ice_tx_buf *tx_buf;

struct sk_buff *skb;

skb_frag_t *frag;

dma_addr_t dma;

bool kick;

  

td_tag = off->td_l2tag1;

td_cmd = off->td_cmd;

td_offset = off->td_offset;

skb = first->skb;

  

data_len = skb->data_len;

size = skb_headlen(skb);

  

tx_desc = ICE_TX_DESC(tx_ring, i);

  

if (first->tx_flags & ICE_TX_FLAGS_HW_VLAN) {

td_cmd |= (u64)ICE_TX_DESC_CMD_IL2TAG1;

td_tag = first->vid;

}

  

dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);

  

tx_buf = first;

  

for (frag = &skb_shinfo(skb)->frags[0];; frag++) {

unsigned int max_data = ICE_MAX_DATA_PER_TXD_ALIGNED;

  

if (dma_mapping_error(tx_ring->dev, dma))

goto dma_error;

  

/* record length, and DMA address */

dma_unmap_len_set(tx_buf, len, size);

dma_unmap_addr_set(tx_buf, dma, dma);

  

/* align size to end of page */

max_data += -dma & (ICE_MAX_READ_REQ_SIZE - 1);

tx_desc->buf_addr = cpu_to_le64(dma);

  

/* account for data chunks larger than the hardware

* can handle

*/

while (unlikely(size > ICE_MAX_DATA_PER_TXD)) {

tx_desc->cmd_type_offset_bsz =

ice_build_ctob(td_cmd, td_offset, max_data,

td_tag);

  

tx_desc++;

i++;

  

if (i == tx_ring->count) {

tx_desc = ICE_TX_DESC(tx_ring, 0);

i = 0;

}

  

dma += max_data;

size -= max_data;

  

max_data = ICE_MAX_DATA_PER_TXD_ALIGNED;

tx_desc->buf_addr = cpu_to_le64(dma);

}

  

if (likely(!data_len))

break;

  

tx_desc->cmd_type_offset_bsz = ice_build_ctob(td_cmd, td_offset,

size, td_tag);

  

tx_desc++;

i++;

  

if (i == tx_ring->count) {

tx_desc = ICE_TX_DESC(tx_ring, 0);

i = 0;

}

  

size = skb_frag_size(frag);

data_len -= size;

  

dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size,

DMA_TO_DEVICE);

  

tx_buf = &tx_ring->tx_buf[i];

tx_buf->type = ICE_TX_BUF_FRAG;

}

  

/* record SW timestamp if HW timestamp is not available */

skb_tx_timestamp(first->skb);

  

i++;

if (i == tx_ring->count)

i = 0;

  

/* write last descriptor with RS and EOP bits */

td_cmd |= (u64)ICE_TXD_LAST_DESC_CMD;

tx_desc->cmd_type_offset_bsz =

ice_build_ctob(td_cmd, td_offset, size, td_tag);

  

/* Force memory writes to complete before letting h/w know there

* are new descriptors to fetch.

*

* We also use this memory barrier to make certain all of the

* status bits have been updated before next_to_watch is written.

*/

wmb();

  

/* set next_to_watch value indicating a packet is present */

first->next_to_watch = tx_desc;

  

tx_ring->next_to_use = i;

  

ice_maybe_stop_tx(tx_ring, DESC_NEEDED);

  

/* notify HW of packet */

kick = __netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount,

netdev_xmit_more());

if (kick)

/* notify HW of packet */

writel(i, tx_ring->tail);

  

return;

  

dma_error:

/* clear DMA mappings for failed tx_buf map */

for (;;) {

tx_buf = &tx_ring->tx_buf[i];

ice_unmap_and_free_tx_buf(tx_ring, tx_buf);

if (tx_buf == first)

break;

if (i == 0)

i = tx_ring->count;

i--;

}

  

tx_ring->next_to_use = i;

}
```


```c title=ice_tx_map()
/**

* ice_tx_map - Build the Tx descriptor

* @tx_ring: ring to send buffer on

* @first: first buffer info buffer to use

* @off: pointer to struct that holds offload parameters

*

* This function loops over the skb data pointed to by *first

* and gets a physical address for each memory location and programs

* it and the length into the transmit descriptor.

*/

static void

ice_tx_map(struct ice_tx_ring *tx_ring, struct ice_tx_buf *first,

struct ice_tx_offload_params *off)

{

u64 td_offset, td_tag, td_cmd;

u16 i = tx_ring->next_to_use;

unsigned int data_len, size;

struct ice_tx_desc *tx_desc;

struct ice_tx_buf *tx_buf;

struct sk_buff *skb;

skb_frag_t *frag;

dma_addr_t dma;

bool kick;

  

td_tag = off->td_l2tag1;

td_cmd = off->td_cmd;

td_offset = off->td_offset;

skb = first->skb;

  

data_len = skb->data_len;

size = skb_headlen(skb);

  

tx_desc = ICE_TX_DESC(tx_ring, i);

  

if (first->tx_flags & ICE_TX_FLAGS_HW_VLAN) {

td_cmd |= (u64)ICE_TX_DESC_CMD_IL2TAG1;

td_tag = first->vid;

}

  

dma = dma_map_single(tx_ring->dev, skb->data, size, DMA_TO_DEVICE);

  

tx_buf = first;

  

for (frag = &skb_shinfo(skb)->frags[0];; frag++) {

unsigned int max_data = ICE_MAX_DATA_PER_TXD_ALIGNED;

  

if (dma_mapping_error(tx_ring->dev, dma))

goto dma_error;

  

/* record length, and DMA address */

dma_unmap_len_set(tx_buf, len, size);

dma_unmap_addr_set(tx_buf, dma, dma);

  

/* align size to end of page */

max_data += -dma & (ICE_MAX_READ_REQ_SIZE - 1);

tx_desc->buf_addr = cpu_to_le64(dma);

  

/* account for data chunks larger than the hardware

* can handle

*/

while (unlikely(size > ICE_MAX_DATA_PER_TXD)) {

tx_desc->cmd_type_offset_bsz =

ice_build_ctob(td_cmd, td_offset, max_data,

td_tag);

  

tx_desc++;

i++;

  

if (i == tx_ring->count) {

tx_desc = ICE_TX_DESC(tx_ring, 0);

i = 0;

}

  

dma += max_data;

size -= max_data;

  

max_data = ICE_MAX_DATA_PER_TXD_ALIGNED;

tx_desc->buf_addr = cpu_to_le64(dma);

}

  

if (likely(!data_len))

break;

  

tx_desc->cmd_type_offset_bsz = ice_build_ctob(td_cmd, td_offset,

size, td_tag);

  

tx_desc++;

i++;

  

if (i == tx_ring->count) {

tx_desc = ICE_TX_DESC(tx_ring, 0);

i = 0;

}

  

size = skb_frag_size(frag);

data_len -= size;

  

dma = skb_frag_dma_map(tx_ring->dev, frag, 0, size,

DMA_TO_DEVICE);

  

tx_buf = &tx_ring->tx_buf[i];

tx_buf->type = ICE_TX_BUF_FRAG;

}

  

/* record SW timestamp if HW timestamp is not available */

skb_tx_timestamp(first->skb);

  

i++;

if (i == tx_ring->count)

i = 0;

  

/* write last descriptor with RS and EOP bits */

td_cmd |= (u64)ICE_TXD_LAST_DESC_CMD;

tx_desc->cmd_type_offset_bsz =

ice_build_ctob(td_cmd, td_offset, size, td_tag);

  

/* Force memory writes to complete before letting h/w know there

* are new descriptors to fetch.

*

* We also use this memory barrier to make certain all of the

* status bits have been updated before next_to_watch is written.

*/

wmb();

  

/* set next_to_watch value indicating a packet is present */

first->next_to_watch = tx_desc;

  

tx_ring->next_to_use = i;

  

ice_maybe_stop_tx(tx_ring, DESC_NEEDED);

  

/* notify HW of packet */

kick = __netdev_tx_sent_queue(txring_txq(tx_ring), first->bytecount,

netdev_xmit_more());

if (kick)

/* notify HW of packet */

writel(i, tx_ring->tail);

  

return;

  

dma_error:

/* clear DMA mappings for failed tx_buf map */

for (;;) {

tx_buf = &tx_ring->tx_buf[i];

ice_unmap_and_free_tx_buf(tx_ring, tx_buf);

if (tx_buf == first)

break;

if (i == 0)

i = tx_ring->count;

i--;

}

  

tx_ring->next_to_use = i;

}
```

/include/linux/netdevice.h

```c title=__netdev_tx_sent_queue()
/* Variant of netdev_tx_sent_queue() for drivers that are aware

* that they should not test BQL status themselves.

* We do want to change __QUEUE_STATE_STACK_XOFF only for the last

* skb of a batch.

* Returns true if the doorbell must be used to kick the NIC.

*/

static inline bool __netdev_tx_sent_queue(struct netdev_queue *dev_queue,

unsigned int bytes,

bool xmit_more)

{

if (xmit_more) {

#ifdef CONFIG_BQL

dql_queued(&dev_queue->dql, bytes);

#endif

return netif_tx_queue_stopped(dev_queue);

}

netdev_tx_sent_queue(dev_queue, bytes);

return true;

}
```


```c title=netdev_tx_sent_queue()
/**

* netdev_tx_sent_queue - report the number of bytes queued to a given tx queue

* @dev_queue: network device queue

* @bytes: number of bytes queued to the device queue

*

* Report the number of bytes queued for sending/completion to the network

* device hardware queue. @bytes should be a good approximation and should

* exactly match netdev_completed_queue() @bytes.

* This is typically called once per packet, from ndo_start_xmit().

*/

static inline void netdev_tx_sent_queue(struct netdev_queue *dev_queue,

unsigned int bytes)

{

#ifdef CONFIG_BQL

dql_queued(&dev_queue->dql, bytes);

  

if (likely(dql_avail(&dev_queue->dql) >= 0))

return;

  

set_bit(__QUEUE_STATE_STACK_XOFF, &dev_queue->state);

  

/*

* The XOFF flag must be set before checking the dql_avail below,

* because in netdev_tx_completed_queue we update the dql_completed

* before checking the XOFF flag.

*/

smp_mb();

  

/* check again in case another CPU has just made room avail */

if (unlikely(dql_avail(&dev_queue->dql) >= 0))

clear_bit(__QUEUE_STATE_STACK_XOFF, &dev_queue->state);

#endif

}
```