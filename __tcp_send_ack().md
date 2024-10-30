```c
/* This routine sends an ack and also updates the window. */

void __tcp_send_ack(struct sock *sk, u32 rcv_nxt)

{

    struct sk_buff *buff;

  

    /* If we have been reset, we may not send again. */

    if (sk->sk_state == TCP_CLOSE)

        return;

  

    /* We are not putting this on the write queue, so

     * tcp_transmit_skb() will set the ownership to this

     * sock.

     */

    buff = alloc_skb(MAX_TCP_HEADER,

             sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN));

    if (unlikely(!buff)) {

        struct inet_connection_sock *icsk = inet_csk(sk);

        unsigned long delay;

  

        delay = TCP_DELACK_MAX << icsk->icsk_ack.retry;

        if (delay < TCP_RTO_MAX)

            icsk->icsk_ack.retry++;

        inet_csk_schedule_ack(sk);

        icsk->icsk_ack.ato = TCP_ATO_MIN;

        inet_csk_reset_xmit_timer(sk, ICSK_TIME_DACK, delay, TCP_RTO_MAX);

        return;

    }

  

    /* Reserve space for headers and prepare control bits. */

    skb_reserve(buff, MAX_TCP_HEADER);

    tcp_init_nondata_skb(buff, tcp_acceptable_seq(sk), TCPHDR_ACK);

  

    /* We do not want pure acks influencing TCP Small Queues or fq/pacing

     * too much.

     * SKB_TRUESIZE(max(1 .. 66, MAX_TCP_HEADER)) is unfortunately ~784

     */

    skb_set_tcp_pure_ack(buff);

  

    /* Send it off, this clears delayed acks for us. */

    __tcp_transmit_skb(sk, buff, 0, (__force gfp_t)0, rcv_nxt);

}
```