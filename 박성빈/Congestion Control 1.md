# 1. 어디서부터 시작할까
## 1. sysctl_net_ipv4.c
``` C
// net/ipv4/sysctl_net_ipv4.c
    {
        .procname   = "tcp_congestion_control",
        .data       = &init_net.ipv4.tcp_congestion_control,
        .mode       = 0644,
        .maxlen     = TCP_CA_NAME_MAX,
        .proc_handler   = proc_tcp_congestion_control,
    },
```

``` C
// net/ipv4/sysctl_net_ipv4.c
static int proc_tcp_congestion_control(struct ctl_table *ctl, int write,
                       void *buffer, size_t *lenp, loff_t *ppos)
{
    struct net *net = container_of(ctl->data, struct net,
                       ipv4.tcp_congestion_control);
    char val[TCP_CA_NAME_MAX];
    struct ctl_table tbl = {
        .data = val,
        .maxlen = TCP_CA_NAME_MAX,
    };

    int ret;
    tcp_get_default_congestion_control(net, val);
    ret = proc_dostring(&tbl, write, buffer, lenp, ppos);
    if (write && ret == 0)
        ret = tcp_set_default_congestion_control(net, val);
    return ret;
}
```

sysctl으로 조정할 수 있는 항목중에 congestion control과 관련된 부분이 있는데, 위 항목이 그것으로 어떤 congestion control을 쓸지 조회/변경할 수 있음.
![[Pasted image 20241106205142.png]]
(write의 값에 따라 0이면 조회, 1이면 수정의 기능을 제공)

## 2. tcp_cong.c
``` c
// net/ipv4/tcp_cong.c
int tcp_register_congestion_control(struct tcp_congestion_ops *ca)
{
    int ret = 0;
    /* all algorithms must implement these */
    if (!ca->ssthresh || !ca->undo_cwnd ||
        !(ca->cong_avoid || ca->cong_control)) {
        pr_err("%s does not implement required ops\n", ca->name);
        return -EINVAL;
    }

    ca->key = jhash(ca->name, sizeof(ca->name), strlen(ca->name));

	spin_lock(&tcp_cong_list_lock);
    if (ca->key == TCP_CA_UNSPEC || tcp_ca_find_key(ca->key)) {
        pr_notice("%s already registered or non-unique key\n",
              ca->name);
        ret = -EEXIST;
    } else {
        list_add_tail_rcu(&ca->list, &tcp_cong_list);
        pr_debug("%s registered\n", ca->name);
    }
    spin_unlock(&tcp_cong_list_lock);

    return ret;
}
```

위 `net/ipv4/sysctl_net_ipv4.c`의 `proc_tcp_congestion_control`함수를 타고 들어가면 `tcp_cong.c`에서 구현됨을 확인할 수 있음. 위 코드가 그 중 일부인데, ca에서 ssthresh, cwnd 등이 제대로 선언되었는지 확인하는 모습
![[Pasted image 20241106205326.png]]

## 3. tcp_cubic.c
``` c
// net/ipv4/tcp_cubic.c
static struct tcp_congestion_ops cubictcp __read_mostly = {
    .init       = bictcp_init,
    .ssthresh   = bictcp_recalc_ssthresh,
    .cong_avoid = bictcp_cong_avoid,
    .set_state  = bictcp_state,
    .undo_cwnd  = tcp_reno_undo_cwnd,
    .cwnd_event = bictcp_cwnd_event,
    .pkts_acked     = bictcp_acked,
    .owner      = THIS_MODULE,
    .name       = "cubic",
};
```

cubic이 구현된 내용이 있는 코드임. `tcp_congestion_ops` 구조체에 혼잡제어에 필요한 항목들을 함수포인터로 넘겨줌. 
![[Pasted image 20241106205040.png]]
### reno vs cubic - ssthresh
1. reno
``` c
u32 tcp_reno_ssthresh(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk); 

    return max(tp->snd_cwnd >> 1U, 2U);
}
```
2. cubic
``` c
// beta: 717, BICTCP_BETA_SCALE: 1024
static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
    const struct tcp_sock *tp = tcp_sk(sk);
    struct bictcp *ca = inet_csk_ca(sk);  
	...
    return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}
```
reno는 `ssthresh`를 윈도우의 절반으로 만드는데 비해, cubic은 `ssthresh`를 0.7배(beta/BICTCP_BETA_SCALE = 717/1024 = 0.7)로 만듬

### reno vs cubic - congestion avoid
1. reno
``` c
// net/ipv4/tcp_cong.c
void tcp_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked)
{
    /* If credits accumulated at a higher w, apply them gently now. */
    if (tp->snd_cwnd_cnt >= w) {
        tp->snd_cwnd_cnt = 0;
        tp->snd_cwnd++;
    }

    tp->snd_cwnd_cnt += acked;
    if (tp->snd_cwnd_cnt >= w) {
        u32 delta = tp->snd_cwnd_cnt / w;

        tp->snd_cwnd_cnt -= delta * w;
        tp->snd_cwnd += delta;
    }
    tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);
}

void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);  

    if (!tcp_is_cwnd_limited(sk))
        return;

    /* In "safe" area, increase. */
    if (tcp_in_slow_start(tp)) {
        acked = tcp_slow_start(tp, acked);
        if (!acked)
            return;
    }
    /* In dangerous area, increase slowly. */
    tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}
```

2. cubic
``` c
// net/ipv4/tcp_cubic.c

static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct bictcp *ca = inet_csk_ca(sk);

    if (!tcp_is_cwnd_limited(sk))
        return;

    if (tcp_in_slow_start(tp)) {
        if (hystart && after(ack, ca->end_seq))
            bictcp_hystart_reset(sk);
        acked = tcp_slow_start(tp, acked);
        if (!acked)
            return;
    }
    bictcp_update(ca, tp->snd_cwnd, acked);
    tcp_cong_avoid_ai(tp, ca->cnt, acked);
}
```

``` c
// net/ipv4/tcp_cubic.c
static inline void bictcp_update(struct bictcp *ca, u32 cwnd, u32 acked)
{
	...
	t = (s32)(tcp_jiffies32 - ca->epoch_start);
    t += usecs_to_jiffies(ca->delay_min);
    /* change the unit from HZ to bictcp_HZ */
    t <<= BICTCP_HZ;
    do_div(t, HZ);

    if (t < ca->bic_K)      /* t - K */
        offs = ca->bic_K - t;
    else
        offs = t - ca->bic_K;
    
    /* c/rtt * (t-K)^3 */
    delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
    if (t < ca->bic_K)                            /* below origin*/
        bic_target = ca->bic_origin_point - delta;
    else                                          /* above origin*/
        bic_target = ca->bic_origin_point + delta;

    /* cubic function - calc bictcp_cnt*/
    if (bic_target > cwnd) {
        ca->cnt = cwnd / (bic_target - cwnd);
    } else {
        ca->cnt = 100 * cwnd;              /* very small increment*/
    }
    ...
}
```

`hystart`를 초기화하는 코드와 `bictcp_update`가 새로 생긴 모습
`delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ) = (cube_rtt_scale/2¹⁰) * (offs/2¹⁰)³`
`bic_target`과 `cwnd`와의 차이가 크면 `ca->cnt`의 값을 줄이고, 이는 위의 `tcp_cong_avoid_ai`에서 `ca->cnt`만큼 나눠서 나온 몫만큼 윈도우 크기를 키워서 더 빨라짐
# 2. Congestion Control은 언제 발동되나?
![[Pasted image 20241106220042.png]]
(cubic은 아니지만...)
## 1. ssthresh
### timeout
``` c
// net/ipv4/tcp_input.c
void tcp_enter_loss(struct sock *sk)
{
    const struct inet_connection_sock *icsk = inet_csk(sk);
    struct tcp_sock *tp = tcp_sk(sk);
    struct net *net = sock_net(sk);
    bool new_recovery = icsk->icsk_ca_state < TCP_CA_Recovery;  

    tcp_timeout_mark_lost(sk);

    /* Reduce ssthresh if it has not yet been made inside this window. */
    if (icsk->icsk_ca_state <= TCP_CA_Disorder ||
        !after(tp->high_seq, tp->snd_una) ||
        (icsk->icsk_ca_state == TCP_CA_Loss && !icsk->icsk_retransmits)) {
        tp->prior_ssthresh = tcp_current_ssthresh(sk);
        tp->prior_cwnd = tp->snd_cwnd;
        tp->snd_ssthresh = icsk->icsk_ca_ops->ssthresh(sk);
        tcp_ca_event(sk, CA_EVENT_LOSS);
        tcp_init_undo(tp);
    }
    tp->snd_cwnd       = tcp_packets_in_flight(tp) + 1;
    tp->snd_cwnd_cnt   = 0;
    tp->snd_cwnd_stamp = tcp_jiffies32;

    /* Timeout in disordered state after receiving substantial DUPACKs
     * suggests that the degree of reordering is over-estimated.
     */
    if (icsk->icsk_ca_state <= TCP_CA_Disorder &&
        tp->sacked_out >= net->ipv4.sysctl_tcp_reordering)
        tp->reordering = min_t(unsigned int, tp->reordering,
                       net->ipv4.sysctl_tcp_reordering);
    tcp_set_ca_state(sk, TCP_CA_Loss);
    tp->high_seq = tp->snd_nxt;
    tcp_ecn_queue_cwr(tp);

    /* F-RTO RFC5682 sec 3.1 step 1: retransmit SND.UNA if no previous
     * loss recovery is underway except recurring timeout(s) on
     * the same SND.UNA (sec 3.2). Disable F-RTO on path MTU probing
     */

    tp->frto = net->ipv4.sysctl_tcp_frto &&
           (new_recovery || icsk->icsk_retransmits) &&
           !inet_csk(sk)->icsk_mtup.probe_size;
}
```

``` c
// net/ipv4/tcp_timer.c
void tcp_retransmit_timer(struct sock *sk)
{
    struct tcp_sock *tp = tcp_sk(sk);
    struct net *net = sock_net(sk);
    struct inet_connection_sock *icsk = inet_csk(sk);
    struct request_sock *req;
    struct sk_buff *skb;
	...
    if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
        !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
        /* Receiver dastardly shrinks window. Our retransmits
         * become zero probes, but we should not timeout this
         * connection. If the socket is an orphan, time it out,
         * we cannot allow such beasts to hang infinitely.
         */
		...
        tcp_enter_loss(sk);
        tcp_retransmit_skb(sk, skb, 1);
        __sk_dst_reset(sk);
        goto out_reset_timer;
    }
	...
	tcp_enter_loss(sk);
	...
}
```

![[Pasted image 20241107210654.png]]

tcp 소켓을 생성할 때 `inet_csk_init_xmit_timers`를 통해서 타이머를 설정함. 타이머의 콜백은 `tcp_write_timer`인데, 이 함수를 통해 이후 위의 `tcp_retransmit_timer`까지 불리게 됨

``` c
    if (!tp->snd_wnd && !sock_flag(sk, SOCK_DEAD) &&
        !((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))) {
        ...
        tcp_enter_loss(sk);
        ...
		goto out_reset_timer;
	}
```
- `!tp->snd_wnd` : window가 0. 더 보낼 데이터가 없음
- `!sock_flag(sk, SOCK_DEAD)` : 소켓이 살아 있음
- `!((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))` : 현재 state가 `TCPF_SYN_SENT`와 `TCPF_SYN_RECV`이 아님. => 3way handshake중이 아닌 것, 즉 정상 TCP



### dupack
``` c
// include/net/tcp.h
static inline bool tcp_is_reno(const struct tcp_sock *tp)
{
    return !tcp_is_sack(tp);
}
```
``` c
// net/ipv4/tcp_input.c
/* Emulate SACKs for SACKless connection: account for a new dupack. */
static void tcp_add_reno_sack(struct sock *sk, int num_dupack, bool ece_ack)
{
    if (num_dupack) {
        struct tcp_sock *tp = tcp_sk(sk);
        u32 prior_sacked = tp->sacked_out;
        s32 delivered;

        tp->sacked_out += num_dupack;
        tcp_check_reno_reordering(sk, 0);
        delivered = tp->sacked_out - prior_sacked;
        if (delivered > 0)
            tcp_count_delivered(tp, delivered, ece_ack);
        tcp_verify_left_out(tp);
    }
}
```

reno를 제외하고는 `dupack`을 사용하지 않는 듯함. 위와 같이 `dupack`이 있는 reno를 지원하기 위한 인터페이스도 따로 존재. `sack`을 주로 사용하는 듯

### sack
``` c
// net/ipv4/tcp_input.c
static int tcp_ack(struct sock *sk, const struct sk_buff *skb, int flag)
{
	...
	tcp_fastretrans_alert(sk, prior_snd_una, num_dupack, &flag, &rexmit);
	...
}

static void tcp_fastretrans_alert(struct sock *sk, const u32 prior_snd_una,
                  int num_dupack, int *ack_flag, int *rexmit)
{
	...
	if (!tcp_is_rack(sk) && do_lost)
        tcp_update_scoreboard(sk, fast_rexmit);
    *rexmit = REXMIT_LOST;
}

static void tcp_update_scoreboard(struct sock *sk, int fast_rexmit)
{
    struct tcp_sock *tp = tcp_sk(sk);

    if (tcp_is_sack(tp)) {
        int sacked_upto = tp->sacked_out - tp->reordering;
        if (sacked_upto >= 0)
            tcp_mark_head_lost(sk, sacked_upto, 0);
        else if (fast_rexmit)
            tcp_mark_head_lost(sk, 1, 1);
    }
}

static void tcp_mark_head_lost(struct sock *sk, int packets, int mark_head)
{
	...
	skb_rbtree_walk_from(skb) {
		...
        if (!(TCP_SKB_CB(skb)->sacked & TCPCB_LOST))
            tcp_mark_skb_lost(sk, skb);
        ...
    }
    ...
}

void tcp_mark_skb_lost(struct sock *sk, struct sk_buff *skb)
{
    __u8 sacked = TCP_SKB_CB(skb)->sacked;
    struct tcp_sock *tp = tcp_sk(sk);

    if (sacked & TCPCB_SACKED_ACKED)
        return;

    tcp_verify_retransmit_hint(tp, skb);
    if (sacked & TCPCB_LOST) {
        if (sacked & TCPCB_SACKED_RETRANS) {
            /* Account for retransmits that are lost again */
            TCP_SKB_CB(skb)->sacked &= ~TCPCB_SACKED_RETRANS;
            tp->retrans_out -= tcp_skb_pcount(skb);
            NET_ADD_STATS(sock_net(sk), LINUX_MIB_TCPLOSTRETRANSMIT,
                      tcp_skb_pcount(skb));
            tcp_notify_skb_loss_event(tp, skb);
        }
    } else {
        tp->lost_out += tcp_skb_pcount(skb);
        TCP_SKB_CB(skb)->sacked |= TCPCB_LOST;
        tcp_notify_skb_loss_event(tp, skb);
    }
}
```

`tcp_update_scoreboard`에서 sack을 보고 이상한 애들은 `tcp_mark_skb_lost`를 통해 다시 보내야 하는 패킷임을 명시

sack과 관련하여 `ssthresh` 조절하는 부분을 찾는 중.