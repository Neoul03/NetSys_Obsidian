드라이버 코드에서 mellanox-mlx5 쪽 코드를 따로 수정한 것을 확인 할 수 있음. 새로운 IPPROTO_VIRTUAL_SOCK 이라는 타입을 추가하면서 발생하는 수정사항으로 보임. 
기본적으로는 IPPROTO_TCP와 같은 취급을 해주면 됨.
ip_proto에 IPPROTO_VIRTUAL_SOCK이 들어감.

tcp_v4_rcv -> nd_rcv가 그 역할을 함.

```c
/* thinking of making this const? Don't.
* early_demux can change based on sysctl.
*/
static struct net_protocol nd_protocol = {
	.early_demux = nd_v4_early_demux,
	.early_demux_handler = nd_v4_early_demux,
	.handler = nd_rcv,
	.err_handler = nd_err,
	.no_policy = 1,
	.netns_ok = 1,
};
```
module의 `nd_plumbing.c`에 있음.

nd_rcv에서는 nd 헤더의 타입별로 핸들러 함수가 각각 나눠져 있는데, data 부분을 살펴보았음.

먼저 `__nd_llokup_skb`함수를 통해 해당하는 소켓을 찾게 되고, 


ndt_conn_alloc_queue에서 원격 core에서 받은 sendmsg request를 처리하는데 쓰이는 work struct인 io_work를 ndt_conn_io_work로 초기화한다.

wait for memory: 에서
`&nsk->sender.in_flight_copy_bytes`가 0이 될 때까지 `schedule()`함수를 통해 본 context가 잠들게 된다.
이게 모두 완료 되었다면, `nd_push()`함수를 호출하게 된다.
이 때 넘어오는 parameter는 `sock` 타입의 `sk`이다.

`nd_fetch_dcopy_response()` 함수를 통해  `&nsk->sender.response_list()`를 `node`에다가 하나씩 담아오게 되는데, node가 `null`이 아닐 때까지 반복하게 된다. 

`nd_dcopy_response`라는 구조체는 `skb` 포인터를 가지고 있는 `llist`의 entry이다. 여기서 `&sk->tcp_rtx_queue`에다가 해당 `skb`를 집어 넣는 것으로 보인다.

`nd_snd_q_ready()`함수를 통해 `sk->sk_write_queue`혹은 `sk->tcp_rtx_queue`에 skb가 있는지 확인하고, 남아있다면 while문을 반복하게 된다.
`nd_dequeue_snd_q()`를 통해 위의 두 큐에서 `skb`를 하나 가져오게 되고, `nd_init_request()`를 통해 request를 초기화 한다. 이는 `nd_conn_request` 타입의 구조체의 `->hdr`를 `page_frag_alloc`을 통해 실질적인 페이지를 할당하게 하기 위함이다.
이후 해당 헤더를 세팅하게 되고, `nd_conn_queue_request()`함수를 통해 실제로 전송하게 된다.

```c
struct nd_conn_request {
	// struct nvme_request	req;
	struct ndhdr	*hdr;
	struct sk_buff	*skb;
	struct nd_conn_queue	*queue;
	int prio_class;
	// u32			data_len;
	// u32			pdu_len;
	// u32			pdu_sent;
	
	u16			ttag;

	struct list_head	entry;
	struct llist_node	lentry;
	// __le32			ddgst;

	// struct bio		*curr_bio;
	struct iov_iter		iter;

	/* send state */
	size_t			offset;
	size_t			data_sent;
	size_t			frag_offset;
	size_t			fragidx;
	enum nd_conn_send_state state;
};
```

특정 큐를 찾은다음, 이 큐에다가 해당 `skb`를 넣고, 만약 현재 core가 해야할 io_work queue라면 바로 실행할 수 있게 `nd_conn_try_send()`함수를 실행하고, 아니라면 그냥 `queue_work_on`함수를 통해 스케줄링하게 된다.

이러한 `nd_conn_try_send()`함수는 여기 말고 `nd_conn_io_work()`라는 함수에서도 호출되는데, 여기서는 해당 `nd_conn_queue`를 끄집어 내서 `nd_conn_try_send()`에 parameter로 들어가서 호출되므로, 이것이 논문에서 이야기하는 worker thread가 실행하는 함수 중 하나인 것으로 보인다.

```c
struct nd_conn_queue {
	int prio_class;
	struct socket		*sock;
	struct work_struct	io_work;
	int			io_cpu;
	int 	qid;
	struct mutex		send_mutex;
	struct llist_head	req_list;
	struct list_head	send_list;
	bool			more_requests;

	/* recv state */
	// void			*pdu;
	// int			pdu_remaining;
	// int			pdu_offset;
	// size_t			data_remaining;
	// size_t			ddgst_remaining;
	// unsigned int		nr_cqe;

	/* send state */
	struct nd_conn_request *request;
	atomic_t	cur_queue_size;
	int			queue_size;
	int			compact_high_thre;
	int 		compact_low_thre;
	// int			cur_queue_size;
	// size_t			cmnd_capsule_len;
	struct nd_conn_ctrl	*ctrl;
	unsigned long		flags;
	bool			rd_enabled;

	// bool			hdr_digest;
	// bool			data_digest;
	// struct ahash_request	*rcv_hash;
	// struct ahash_request	*snd_hash;
	// __le32			exp_ddgst;
	// __le32			recv_ddgst;

	// struct page_frag_cache	pf_cache;
	/* socket wait list */
	spinlock_t sock_wait_lock;
	struct list_head sock_wait_list;
	struct workqueue_struct *sock_wait_wq;
	
	void (*state_change)(struct sock *);
	void (*data_ready)(struct sock *);
	void (*write_space)(struct sock *);
};
```

`nd_conn_fetch_request()`를 통해 `nd_conn_request`를 가져오게 되는데, 여기서는 우선 queue의 send_list에서 가져오고, 없으면 req_list의 각 노드를 처리하여 send_list로 가져온 다음에 처리하게 된다.

`ND_CONN_SEND_CMD_PDU`가 무슨의미인지는 모르겠으나, 일단 쓰이고 있어서 따라갔다. kernel_sendpage를 통해 해당 페이지를 `queue->sock`을 통해 전송하게 된다.

`nd_dcopy_init()`함수에서 보면 `alloc_workqueue()`함수를 통해 data copy를 위한 workqueue를 할당하고 있다.

`msg`에 담겨있는 페이로드를 `bio_vec`로 옮겨서 `nd_dcopy_request`에 담아서 이를 큐잉하게 된다.
이때 `nd_dcopy_iov_init()`함수 내부를 살펴보면 페이지 단위로 포인터를 전달하는 것을 볼 수 있다.