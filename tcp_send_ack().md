```c
void tcp_send_ack(struct sock *sk)
{
	__tcp_send_ack(sk, tcp_sk(sk)->rcv_nxt);
}
```

>ack 번호는 소켓의 rcv_nxt를 받아와서 넘기게 된다.

-> `__tcp_send_ack()`

[[__tcp_send_ack()]]

