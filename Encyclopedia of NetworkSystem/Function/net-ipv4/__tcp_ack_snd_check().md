```c
/*

 * Check if sending an ack is needed.

 */

static void __tcp_ack_snd_check(struct sock *sk, int ofo_possible)

{

    struct tcp_sock *tp = tcp_sk(sk);

    unsigned long rtt, delay;

  

        /* More than one full frame received... */

    if (((tp->rcv_nxt - tp->rcv_wup) > inet_csk(sk)->icsk_ack.rcv_mss &&

         /* ... and right edge of window advances far enough.

          * (tcp_recvmsg() will send ACK otherwise).

          * If application uses SO_RCVLOWAT, we want send ack now if

          * we have not received enough bytes to satisfy the condition.

          */

        (tp->rcv_nxt - tp->copied_seq < sk->sk_rcvlowat ||

         __tcp_select_window(sk) >= tp->rcv_wnd)) ||

        /* We ACK each frame or... */

        tcp_in_quickack_mode(sk) ||

        /* Protocol state mandates a one-time immediate ACK */

        inet_csk(sk)->icsk_ack.pending & ICSK_ACK_NOW) {

        /* If we are running from __release_sock() in user context,

         * Defer the ack until tcp_release_cb().

         */

        if (sock_owned_by_user_nocheck(sk) &&

            READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_backlog_ack_defer)) {

            set_bit(TCP_ACK_DEFERRED, &sk->sk_tsq_flags);

            return;

        }

send_now:

        tcp_send_ack(sk);

        return;

    }

  

    if (!ofo_possible || RB_EMPTY_ROOT(&tp->out_of_order_queue)) {

        tcp_send_delayed_ack(sk);

        return;

    }

  

    if (!tcp_is_sack(tp) ||

        tp->compressed_ack >= READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_comp_sack_nr))

        goto send_now;

  

    if (tp->compressed_ack_rcv_nxt != tp->rcv_nxt) {

        tp->compressed_ack_rcv_nxt = tp->rcv_nxt;

        tp->dup_ack_counter = 0;

    }

    if (tp->dup_ack_counter < TCP_FASTRETRANS_THRESH) {

        tp->dup_ack_counter++;

        goto send_now;

    }

    tp->compressed_ack++;

    if (hrtimer_is_queued(&tp->compressed_ack_timer))

        return;

  

    /* compress ack timer : 5 % of rtt, but no more than tcp_comp_sack_delay_ns */

  

    rtt = tp->rcv_rtt_est.rtt_us;

    if (tp->srtt_us && tp->srtt_us < rtt)

        rtt = tp->srtt_us;

  

    delay = min_t(unsigned long,

              READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_comp_sack_delay_ns),

              rtt * (NSEC_PER_USEC >> 3)/20);

    sock_hold(sk);

    hrtimer_start_range_ns(&tp->compressed_ack_timer, ns_to_ktime(delay),

                   READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_comp_sack_slack_ns),

                   HRTIMER_MODE_REL_PINNED_SOFT);

}
```

[[tcp_send_ack()]]



