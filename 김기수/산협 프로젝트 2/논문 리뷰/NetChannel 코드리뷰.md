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

맨처음 잡히는 `nd_v4_do_rcv`의 경우 `nd_hdr`를 통해 헤더를 가져오게 되는데, 이 헤더는 기존의 transport 헤더부분을 가져오는 것으로, virtual socket이 완전히 대체하고 있음을 알 수 있다.

```c
int nd_conn_alloc_queue(struct nd_conn_ctrl *ctrl,
        int qid)
{
    // struct nvme_tcp_ctrl *ctrl = to_tcp_ctrl(nctrl);
    struct nd_conn_queue *queue = &ctrl->queues[qid];
    struct linger sol = { .l_onoff = 1, .l_linger = 0 };
    int ret, opt, n;
    // int bufsize = 1000000;
    // int optlen = sizeof(bufsize);
    queue->ctrl = ctrl;
    init_llist_head(&queue->req_list);
    INIT_LIST_HEAD(&queue->send_list);
    /* init socket wait list */
    INIT_LIST_HEAD(&queue->sock_wait_list);
    spin_lock_init(&queue->sock_wait_lock);
  
    // spin_lock_init(&queue->lock);
    mutex_init(&queue->send_mutex);
    INIT_WORK(&queue->io_work, nd_conn_io_work);
    queue->queue_size = ctrl->opts->queue_size;
    queue->compact_low_thre = ctrl->opts->compact_low_thre;
    queue->compact_high_thre = ctrl->opts->compact_high_thre;
    atomic_set(&queue->cur_queue_size, 0);
  
  
    if (qid >= ctrl->queue_count / 2) {
        /* latency-sensitive channel */
        queue->prio_class = 1;
    } else
        /* throughput-bound channel */
        queue->prio_class = 0;
    // if (qid > 0)
    //  queue->cmnd_capsule_len = nctrl->ioccsz * 16;
    // else
    //  queue->cmnd_capsule_len = sizeof(struct nvme_command) +
    //                  NVME_TCP_ADMIN_CCSZ;
  
    ret = sock_create(ctrl->addr.ss_family, SOCK_STREAM,
            IPPROTO_TCP, &queue->sock);
    if (ret) {
        pr_err("failed to create socket: %d\n", ret);
        return ret;
    }
  
    /* Single syn retry */
    opt = 1;
    ret = kernel_setsockopt(queue->sock, IPPROTO_TCP, TCP_SYNCNT,
            (char *)&opt, sizeof(opt));
    if (ret) {
        pr_err("failed to set TCP_SYNCNT sock opt %d\n", ret);
        goto err_sock;
    }
    // tcp_sock_set_syncnt(queue->sock->sk, 1);
    /* Set TCP no delay */
    opt = 1;
    ret = kernel_setsockopt(queue->sock, IPPROTO_TCP,
            TCP_NODELAY, (char *)&opt, sizeof(opt));
    if (ret) {
        pr_err("failed to set TCP_NODELAY sock opt %d\n", ret);
        goto err_sock;
    }
    // tcp_sock_set_nodelay(queue->sock->sk);
    /*
     * Cleanup whatever is sitting in the TCP transmit queue on socket
     * close. This is done to prevent stale data from being sent should
     * the network connection be restored before TCP times out.
     */
    ret = kernel_setsockopt(queue->sock, SOL_SOCKET, SO_LINGER,
            (char *)&sol, sizeof(sol));
    if (ret) {
        pr_err("failed to set SO_LINGER sock opt %d\n", ret);
        goto err_sock;
    }
    // sock_no_linger(queue->sock->sk);
    /* Set socket type of service */
    // if (ctrl->opts->tos >= 0) {
    //  opt = ctrl->opts->tos;
    //  ret = kernel_setsockopt(queue->sock, SOL_IP, IP_TOS,
    //          (char *)&opt, sizeof(opt));
    //  if (ret) {
    //      pr_err("failed to set IP_TOS sock opt %d\n", ret);
    //      goto err_sock;
    //  }
    // }
    // if (so_priority > 0)
    //  sock_set_priority(queue->sock->sk, so_priority);
    // if (ctrl->opts->tos >= 0)
    //  ip_sock_set_tos(queue->sock->sk, ctrl->opts->tos);
    // io cpu might be need to be changed later
    // ret = kernel_getsockopt(queue->sock, SOL_SOCKET, SO_SNDBUF,
    //  (char *)&bufsize, &optlen);
    // pr_info("ret value:%d\n", ret);
    // pr_info("buffer size sender:%d\n", bufsize);
    // bufsize = 4000000;
    // ret = kernel_setsockopt(queue->sock, SOL_SOCKET, SO_SNDBUF,
    //      (char *)&bufsize, sizeof(bufsize));
    queue->sock->sk->sk_allocation = GFP_ATOMIC;
    if (!qid)
        n = 0;
    else
        n = (qid - 1) % num_online_cpus();
    // queue->io_cpu = cpumask_next_wrap(n - 1, cpu_online_mask, -1, false);
    queue->io_cpu = (nd_params.nr_nodes * qid) % nd_params.nr_cpus;
    // queue->io_cpu = 0;
    queue->qid = qid;
    // printk("queue id:%d\n", queue->io_cpu);
    queue->request = NULL;
    // queue->data_remaining = 0;
    // queue->ddgst_remaining = 0;
    // queue->pdu_remaining = 0;
    // queue->pdu_offset = 0;
    sk_set_memalloc(queue->sock->sk);
  
    // if (nctrl->opts->mask & NVMF_OPT_HOST_TRADDR) {
        ret = kernel_bind(queue->sock, (struct sockaddr *)&ctrl->src_addr,
            sizeof(ctrl->src_addr));
        if (ret) {
            pr_err("failed to bind queue %d socket %d\n",qid, ret);
            goto err_sock;
        }
    // }
  
    // queue->hdr_digest = nctrl->opts->hdr_digest;
    // queue->data_digest = nctrl->opts->data_digest;
    // if (queue->hdr_digest || queue->data_digest) {
    //  ret = nvme_tcp_alloc_crypto(queue);
    //  if (ret) {
    //      dev_err(nctrl->device,
    //          "failed to allocate queue %d crypto\n", qid);
    //      goto err_sock;
    //  }
    // }
  
    // rcv_pdu_size = sizeof(struct nvme_tcp_rsp_pdu) +
    //      nvme_tcp_hdgst_len(queue);
    // queue->pdu = kmalloc(rcv_pdu_sze, GFP_KERNEL);
    // if (!queue->pdu) {
    //  ret = -ENOMEM;
    //  goto err_crypto;
    // }

    // dev_dbg(nctrl->device, "connecting queue %d\n",
    //      nvme_tcp_queue_id(queue));
  
    ret = kernel_connect(queue->sock, (struct sockaddr *)&ctrl->addr,
        sizeof(ctrl->addr), 0);
    if (ret) {
        pr_err("failed to connect socket: %d\n", ret);
        goto err_rcv_pdu;
    }
    // this part needed to be handled later
    // ret = nvme_tcp_init_connection(queue);
    if (ret)
        goto err_init_connect;
  
    queue->rd_enabled = true;
    set_bit(ND_CONN_Q_ALLOCATED, &queue->flags);
    // nvme_tcp_init_recv_ctx(queue);
  
    write_lock_bh(&queue->sock->sk->sk_callback_lock);
    queue->sock->sk->sk_user_data = queue;
    queue->state_change = queue->sock->sk->sk_state_change;
    queue->data_ready = queue->sock->sk->sk_data_ready;
    queue->write_space = queue->sock->sk->sk_write_space;
    queue->sock->sk->sk_data_ready = nd_conn_data_ready;
    queue->sock->sk->sk_state_change = nd_conn_state_change;
    queue->sock->sk->sk_write_space = nd_conn_write_space;
#ifdef CONFIG_NET_RX_BUSY_POLL
    queue->sock->sk->sk_ll_usec = 1;
#endif
    write_unlock_bh(&queue->sock->sk->sk_callback_lock);

    return 0;
  
err_init_connect:
    kernel_sock_shutdown(queue->sock, SHUT_RDWR);
err_rcv_pdu:
    // kfree(queue->pdu);
// err_crypto:
//  if (queue->hdr_digest || queue->data_digest)
//      nvme_tcp_free_crypto(queue);
err_sock:
    sock_release(queue->sock);
    queue->sock = NULL;
    return ret;
}
```


![[Pasted image 20241115150440.png]]
뭔가 새로운 포트가 만들어지고 있었음.

nd_sock.c 의 655 번 줄에서 Null Pointer exception이 일어나고 있었음

내가 하고 있는 것. 
1. module을 컴파일 하면서 -pg 옵션을 붙임. 이후 perf 등의 과정에서 함수 이름 심볼을 확인할 수 있을 것이라고 예상함.
2. run_client.sh 40.0.0.3 1 nd 를 하면 자꾸 Killed됨. -> dmesg를 통해 찾아보니 Null Pointer Exception이 일어나고 있었고, `nd_v4_connect` 함수에서 nd_conn_queue_request 함수의 첫 번째 parameter가 `construct_sync_req`함수의 반환 값이지만 이 것이 `NULL`을 반환할 떄가 있어 이를 확인하는 함수를 `nd_conn_queue_request`함수 맨 앞에 삽입하여 모듈을 다시 컴파일 중.

![[Pasted image 20241115155440.png]]


