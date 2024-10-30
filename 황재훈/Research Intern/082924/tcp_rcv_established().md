truesize와 sk_forward_alloc을 비교하는 문장이 보인다. Receive socket buffer에 새로운 패킷 데이터를 추가할 여유 공간이 있는지 확인한다. 공간이 있으면 header prediction은 "hit" (prediction 성공)이다. \_\_skb_pull를 호출해서 TCP 헤더를 제거하고 tcp_queue_rcv() 호출한고, \_\_skb_queue_tail을 호출해서 패킷을 receive socket buffer에 추가한다. 마지막으로, \_\_tcp_ack_snd_check를 호출해서 ACK 전송이 필요하면 전송한다.

만약 여유 공간이 부족하면 느린 경로를 수행한다. tcp_data_queue 함수는 버퍼 공간을 새로 할당하고 데이터 패킷을 소켓 버퍼에 추가한다. 이때 가능하면 receive socket buffer 크기를 자동으로 증가한다. 빠른 경로와 다르게, tcp_data_snd_check를 호출해서 새로운 데이터 패킷을 전송할 수 있으면 전송하고, 끝으로 tcp_ack_snd_check 호출해서 ACK 전송이 필요하면 ACK 패킷을 생성해서 전송한다.

```c
/*
 *	TCP receive function for the ESTABLISHED state.
 *
 *	It is split into a fast path and a slow path. The fast path is
 * 	disabled when:
 *	- A zero window was announced from us - zero window probing
 *        is only handled properly in the slow path.
 *	- Out of order segments arrived.
 *	- Urgent data is expected.
 *	- There is no buffer space left
 *	- Unexpected TCP flags/window values/header lengths are received
 *	  (detected by checking the TCP header against pred_flags)
 *	- Data is sent in both directions. Fast path only supports pure senders
 *	  or pure receivers (this means either the sequence number or the ack
 *	  value must stay constant)
 *	- Unexpected TCP option.
 *
 *	When these conditions are not satisfied it drops into a standard
 *	receive procedure patterned after RFC793 to handle all cases.
 *	The first three cases are guaranteed by proper pred_flags setting,
 *	the rest is checked inline. Fast processing is turned on in
 *	tcp_data_queue when everything is OK.
 */
void tcp_rcv_established(struct sock *sk, struct sk_buff *skb)
{
	enum skb_drop_reason reason = SKB_DROP_REASON_NOT_SPECIFIED;
	const struct tcphdr *th = (const struct tcphdr *)skb->data;
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int len = skb->len;

	/* TCP congestion window tracking */
	trace_tcp_probe(sk, skb);

	tcp_mstamp_refresh(tp);
	if (unlikely(!rcu_access_pointer(sk->sk_rx_dst)))
		inet_csk(sk)->icsk_af_ops->sk_rx_dst_set(sk, skb);
	/*
	 *	Header prediction.
	 *	The code loosely follows the one in the famous
	 *	"30 instruction TCP receive" Van Jacobson mail.
	 *
	 *	Van's trick is to deposit buffers into socket queue
	 *	on a device interrupt, to call tcp_recv function
	 *	on the receive process context and checksum and copy
	 *	the buffer to user space. smart...
	 *
	 *	Our current scheme is not silly either but we take the
	 *	extra cost of the net_bh soft interrupt processing...
	 *	We do checksum and copy also but from device to kernel.
	 */

	tp->rx_opt.saw_tstamp = 0;

	/*	pred_flags is 0xS?10 << 16 + snd_wnd
	 *	if header_prediction is to be made
	 *	'S' will always be tp->tcp_header_len >> 2
	 *	'?' will be 0 for the fast path, otherwise pred_flags is 0 to
	 *  turn it off	(when there are holes in the receive
	 *	 space for instance)
	 *	PSH flag is ignored.
	 */

	if ((tcp_flag_word(th) & TCP_HP_BITS) == tp->pred_flags &&
	    TCP_SKB_CB(skb)->seq == tp->rcv_nxt &&
	    !after(TCP_SKB_CB(skb)->ack_seq, tp->snd_nxt)) {
		int tcp_header_len = tp->tcp_header_len;

		/* Timestamp header prediction: tcp_header_len
		 * is automatically equal to th->doff*4 due to pred_flags
		 * match.
		 */

		/* Check timestamp */
		if (tcp_header_len == sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) {
			/* No? Slow path! */
			if (!tcp_parse_aligned_timestamp(tp, th))
				goto slow_path;

			/* If PAWS failed, check it more carefully in slow path */
			if ((s32)(tp->rx_opt.rcv_tsval - tp->rx_opt.ts_recent) < 0)
				goto slow_path;

			/* DO NOT update ts_recent here, if checksum fails
			 * and timestamp was corrupted part, it will result
			 * in a hung connection since we will drop all
			 * future packets due to the PAWS test.
			 */
		}

		if (len <= tcp_header_len) {
			/* Bulk data transfer: sender */
			if (len == tcp_header_len) {
				/* Predicted packet is in window by definition.
				 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
				 * Hence, check seq<=rcv_wup reduces to:
				 */
				if (tcp_header_len ==
				    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
				    tp->rcv_nxt == tp->rcv_wup)
					tcp_store_ts_recent(tp);

				/* We know that such packets are checksummed
				 * on entry.
				 */
				tcp_ack(sk, skb, 0);
				__kfree_skb(skb);
				tcp_data_snd_check(sk);
				/* When receiving pure ack in fast path, update
				 * last ts ecr directly instead of calling
				 * tcp_rcv_rtt_measure_ts()
				 */
				tp->rcv_rtt_last_tsecr = tp->rx_opt.rcv_tsecr;
				return;
			} else { /* Header too small */
				reason = SKB_DROP_REASON_PKT_TOO_SMALL;
				TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
				goto discard;
			}
		} else {
			int eaten = 0;
			bool fragstolen = false;

			if (tcp_checksum_complete(skb))
				goto csum_error;

			if ((int)skb->truesize > sk->sk_forward_alloc)
				goto step5;

			/* Predicted packet is in window by d
			efinition.
			 * seq == rcv_nxt and rcv_wup <= rcv_nxt.
			 * Hence, check seq<=rcv_wup reduces to:
			 */
			if (tcp_header_len ==
			    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_ALIGNED) &&
			    tp->rcv_nxt == tp->rcv_wup)
				tcp_store_ts_recent(tp);

			tcp_rcv_rtt_measure_ts(sk, skb);

			NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPHPHITS);

			/* Bulk data transfer: receiver */
			skb_dst_drop(skb);
			__skb_pull(skb, tcp_header_len);
			eaten = tcp_queue_rcv(sk, skb, &fragstolen);

			tcp_event_data_recv(sk, skb);

			if (TCP_SKB_CB(skb)->ack_seq != tp->snd_una) {
				/* Well, only one small jumplet in fast path... */
				tcp_ack(sk, skb, FLAG_DATA);
				tcp_data_snd_check(sk);
				if (!inet_csk_ack_scheduled(sk))
					goto no_ack;
			} else {
				tcp_update_wl(tp, TCP_SKB_CB(skb)->seq);
			}

			__tcp_ack_snd_check(sk, 0);
no_ack:
			if (eaten)
				kfree_skb_partial(skb, fragstolen);
			tcp_data_ready(sk);
			return;
		}
	}

slow_path:
	if (len < (th->doff << 2) || tcp_checksum_complete(skb))
		goto csum_error;

	if (!th->ack && !th->rst && !th->syn) {
		reason = SKB_DROP_REASON_TCP_FLAGS;
		goto discard;
	}

	/*
	 *	Standard slow path.
	 */

	if (!tcp_validate_incoming(sk, skb, th, 1))
		return;

step5:
	reason = tcp_ack(sk, skb, FLAG_SLOWPATH | FLAG_UPDATE_TS_RECENT);
	if ((int)reason < 0) {
		reason = -reason;
		goto discard;
	}
	tcp_rcv_rtt_measure_ts(sk, skb);

	/* Process urgent data. */
	tcp_urg(sk, skb, th);

	/* step 7: process the segment text */
	tcp_data_queue(sk, skb);

	tcp_data_snd_check(sk);
	tcp_ack_snd_check(sk);
	return;

csum_error:
	reason = SKB_DROP_REASON_TCP_CSUM;
	trace_tcp_bad_csum(skb);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_CSUMERRORS);
	TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);

discard:
	tcp_drop_reason(sk, skb, reason);
}
```

[[tcp_queue_rcv]]
[[__tcp_ack_snd_check()]]
