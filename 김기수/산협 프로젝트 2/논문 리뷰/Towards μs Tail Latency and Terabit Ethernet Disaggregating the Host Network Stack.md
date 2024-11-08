### Abstract
오늘날의 고도로 통합되고 비범용적인 정적 패킷 프로세싱 파이프라인은 네트워크 스택들 속에 넓게 분포해있는데, 이는 최신 하드웨어의 성능을 100% 끌어낼 수 없었다.
이 논문에서는 `NetChannel`이라는 것을 제안한다. 비통합적인 네트워크 스택 아키텍쳐로, 테라비트 이더넷을 운용하는 μs-스케일의 application을 위한 것이다.
넷채널은 비-통합 아키텍쳐인데, 각 패킷 프로세싱 파이프라인 레이어마다 독립적으로 스케쥴링되고 스케일링이 되는 자원들이 할당된다.
리눅스 네트워크 스택에다가 end-to-end로 넷채널을 실현함으로써, 논문에서는 넷 채널이 새로운 운영 포인들이 가능케 함을 보여 주었다.
- single application thread가 수백Gb의 대역폭을 전부 사용함.
- application thread의 갯수에 독립적으로 여러 코어를 활용한 small message processing에 선형에 근접한 scalability가 가능함.
- 쓰루풋을 다 쓰는 application이 실행됨과 동시에 latency에 민감한 application의 isolation이 가능함.

### Introduction
오늘날 리눅스 네트워크 스택의 한계점으로 지목되는 가장 큰 점은 비효율적인 패킷 프로세싱 파이프라인이다. 이는 레이턴시에 민감한 것과 쓰루 풋을 다쓰는 application을 서로 분리할 수 없고, 그 구현이 복잡하고 유연하지 못하며 4계층이 비효율적이라는 단점을 가지고 있다.
이러한 문제점들에 대한 해결책으로 대부분 리눅스 네트워크 스택을 새롭게 구성하는 디자인을 중점적으로 개선방향이 나왔다.
그러나 이 논문에서는 리눅스 네트워크 스택의 문제점이 인터페이스, semantics, placement가 문제가 아닌 코어 아키텍쳐에 문제가 있다는 것을 시사한다. 특히, 리눅스가 탄생 된 이후로 리눅스 네트워크 스택은 application에 유연하지 못한 모두 일률적인 아키텍처로 디자인된 추상화된 파이프를 제공했다.
이러한 아키텍쳐는 아래와 같은 특징을 가진다.
- 특정 목적의 파이프 : 각 application은 데이터를 특정 파이프에 집어 넣고, 네트워크 스택은 이를 다른 파이프 끝에 전달하려고 시도한다.
- 치밀하게 통합되어있는 패킷 프로세싱 파이프라인 : 각각의 파이프는 각각 소유하고 있는 소켓에 할당되며, 각 소켓은 독립적인 4계층 동작을 하게 된다. 이는 외부적인 리소스, 혹은 다른 파이프를 고려하지 않는다.
- 정적인 파이프 : 패킷 프로세싱 파이프라인 전체가 파이프가 만들어질 때 동시에 결정된다. 따라서 외부 환경이 바뀌면서 이를 동적으로 사용할 수 없게 된다.
옛날에는 bottleneck이 이러한 아키텍처를 통해 적절하게 처리되었기 때문에 이러한 디자인은 초기 인터넷 환경에 적합하였다.
그러나 오늘날에는 대역폭이 급격하게 증가함에 따라 bottleneck이 host쪽으로 전가되었다.
따라서 타이트하게 짜여진 네트워크 스택을 다시 아키텍처를 만들어내는 것이 본 논문의 목표이다.

##### The NetChannel architecture
넷채널 아키텍처의 경우 크게 3개의 느슨하게 결합된 레이어로 구성되어 있다.
Application과 직접적으로 상호작용하는 레이어는 Virtual Network System이다. 이 레이어는 streaming과 RPC traffic을 위한 system call을 처리하기 위한 표준 인터페이스를 제공한다.
내부적으로 VNS는 인터페이스 그 자체로 정확성을 보장하면서 application buffer와 kernel buffer간의 데이터 이동이 가능하다.

넷채널의 핵심은 NetDriver 레이어이다. 이 레이어는 네트워크와  원격 서버를 multi-queue-device로 가상화시킨다. 이때 channel abstraction을 이용한다.
특히 NetDriver 레이어는 패킷 프로세싱을 각 application buffer와 core에서 분리시키게 된다. 따라서 한코어에서 application에 의해 실행되는 데이터 읽기/쓰기는 하나 이상의 channel들로 매핑되게 된다. 이때 application은 breaking되지 않는다.
각각의 채널들은 protocol-specific한 함수들이 구현되어 있고, 동적으로 하드웨어 큐에 매핑될 수 있다.
따라서 이러한 가상화를 통해 몇 개의 application이 얼마나 많은 코어에서 돌아가고 있는지 상관없이 채널이 매핑될 수 있다.

이러한 NetDriver와 VNS 사이에는 NetScheduler 레이어가 있다. 이는 각각의 application에서 각각의 channel로 각 코어의 utilization과 application buffer occupancy, channel buffer occupancy 등의 정보를 바탕으로 데이터를 멀티플렉싱 / 디멀티플렉싱을 해주는 레이어이다.

##### NetChannel benefits
넷채널의 장점은 현재 존제하는 프로토콜 처리 구현을 수정할 필요 없이 새롭게 동작 포인트를 만들 수 있다는 것이다.
이 포인트는 넷채널의 분리된 아키텍처의 직접적인 결과이다. 이는 각 레이어의 독립적인 scaling이 가능할 뿐만 아니라, 다중 channel을 통해 유연하게 멀티플렉싱과 디멀티플렉싱을 할 수 있다는 점이다.
네트워크 성능을 높이기 위해 application developer들이 더 이상 코드를 튜닝하지 않아도 된다. 본 넷채널에서 최대한의 성능을 뽑아낼 수 있기 때문이다.
또한 넷채널에서는 새로운 4계층 프로토콜의 구현에 있어서 기존의 호스트를 분해하지 않고 새롭게 디자인 할 수 있으며, 이는 실험하는데 있어서 더욱 쉽다.
이 새로운 프로토콜의 구현은 데이터 복사, 레이턴시 기반/ 대역폭 기반 통신의 분리, CPU 스케쥴링, 로드 밸런싱의 문제들을 고려할 필요가 없어진다.
따라서 결과적으로 스토리지 스택과 비슷하다.

##### What this paper is not about
넷채널 아키텍처는 zero-copy mechanisms과 io_uring interface에 대한 보충이다.
io_uring을 넷채널 아키텍처에 사용하였을 때 좋다는 것 또한 보여줄 것이다.
한정된 CPU 속도와, 수백 기가비트의 대역폭에 따라, 멀티 코어 네트워크 프로세싱은 필수불가결이고, 따라서 넷채널 아키텍쳐는 호스트의 모든 리소스를 최대한 사용하는 것에 집중하였다.
두 번째로, 넷채널 아키텍처는 어디에 있든 상관 없다는 것이다. 커널에 있든 userspace에 있든 하드웨어에 있든 상관 없다. 본 연구에서는 리눅스 커널에서 구현하기로 하였다.
추후 연구 과제로는 넷체널이 userspace와 hardware network stacks에 통합되는 것을 탐색할 것이다.

### Motivation
여기서는 기존의 리눅스커널이 다방면으로 부족하다는 것을 보여주기 위해 다양한 전송 디자인에서 그 성능을 측정하였다.
- Understanding of Host network stack 논문에서 보았듯이, 최대 60Gbps까지 성능이 안나왔고, 이에 대한 bottleneck은 receiver side의 core였다. 이는 오늘날의 네트워크 스택이 동적으로 resource를 할당해주지 않기 때문이다.
- 연결의 갯수를 동적으로 지정하지 못하는 것 또한 bottleneck의 원인중 하나이다. 이는 short message들에 대하여 scalability를 달성하지 못하기 때문이다.
- L-app과 T-app에 대하여 steering을 하지 않는 것 또한 오늘날 리눅스커널의 문제이다. 이를 스티어링하는 메커니즘이 존재하지 않아(다른 코어로 옮겨준다던가) 둘의 경쟁이 일어나고 이는 L-app의 성능저하를 일으킨다.
##### 2.1 Measurement Setup
기존 커널들의 다양한 환경에서 성능을 측정할 방법을 제시하고 있다.
##### 2.2 Limitations of Existing kernel Stack
1) Static and dedicated pipeline => lack of scalability for long flows.
	각종 기술들을 적용해도 100Gbps를 saturate하지는 못했다. 
	새로 찾은 것은 aRFS를 끄고 수동으로 패킷을 스티어링 했을 때, 실제 성능이 조금 더 상승했다는 것이다. 이는 NUMA가 활성화 된 시스템에서 같은 NUMA 노드의 다른 코어로 패킷 프로세싱을 맡김으로써 application이 동작하는 core 입장에서는 offload가 된 것과 같은 효과를 가지기 때문이다.
	이러한 노력에도 불구하고 결국에는 Saturate 되지 못했는데, 여전히 data copy가 주요한 오버헤드로 작용하고 있기 때문이다.
	추가적으로 MPTCP를 사용했을 때도 aRFS를 사용했을 때 최고 성능을 보여준다. 몇 개의 subflow를 사용하던지 간에 모든 처리가 application이 실행중인 코어에서 일어나게 된다. 이러한 이유로 인해 오히려 subflow가 늘어나면 처리해야 할 네트워크 프로세싱 작업이 늘어나므로 총 쓰루풋은 감소하게 된다.
	여기서 aRFS가 없다면 NUMA모드에서는 다른 코어에 할당 될 경우가 존재하므로 매우 낮은 성능을 보여주게 된다. 따라서 aRFS가 필수적이다.
	결론적으로 설정에 상관없이, 여기서는 해당 application이 동작중인 코어에서만 packet processing이 이루어지고, 다른 코어들은 idle 상태이기 때문에, host의 절대적인 전체 성능을 다 사용할 수가 없다는 것을 꼬집고 있다. 심지어 zero-copy mechanism을 사용하더라도 여전이 one core processing pipeline으로 인해 수백Gbps 스케일의 대역폭을 다 채울 수는 없었다. 따라서 결론은, 멀티코어 프로세싱이 필수불가결이다.
	
2) Static and dedicated pipeline => lack of scalability for short message processing.
	여기서는 4KB짜리 RPC 요청들을 지속적으로 보냈다. 평균적인 성능은 9.88Gbps였다. 여기서 bottleneck은 sender-side였다. 코어 내부의 커널 함수 호출을 조사하였을 때, 주요한 task는 TCP/IP processing이였고, 거의 절반의 CPU cycle을 사용하고 있었다. MPTCP도 도움이 되지 못했는데, 결국 가장 중요한 bottleneck이 sender side에서, application이 동작하는 하나의 코어에서 이루어지는 protocol processing이였기 때문이다.
	이는 application 개발자가 직접 multi-socket을 사용하면 그 오버헤드를 극복할 수 있지만, 그 개발자가 얼마나 해야 적당한 지를 모르는게 문제이다. 게다가 커널 모드에서만 접근 가능한 congestion 정보, CPU 사용량 등 외부 상황을 알아내기가 매우 까다로워 이를 더욱 어렵게 한다.
3) Tightly-integrated pipeline => lack of performance isolation.
	같은 NUMA 노드 안에서 L-app과 T-app을 동시에 돌렸을 때, isolated와 interference의 tail latency는 많은 차이가 있었다. 거의 37배 정도의 레이턴시 차이를 보여주고 있었다. 한 코어에 L-app과 T-app이 겹칠 수 있는 실험 조건을 설정하여 이를 구현하였다.
	이러한 문제에 대한 해결책으로 prioritization 기술을 적용하더라도 이는 해결할 수 없었는데, qdisc 레이어에서 pfifo_fast scheduling policy를 적용하고, CPU scheduling에서 우선순위를 최우선으로 하더라도 가시적인 개선효과를 보지 못했다. 우선 qdisc에서는 TCP Small Queue feature 때문에 많은 양이 qdisc 레이어에 큐잉되지 않기 때문이고, CPU 스케줄링의 경우 우선 IRQ thread에서 주요한 네트워크 프로세싱이 일어나므로 우선순위가 큰 영향을 미치지 않고, IRQ processing은 non-preemptive 이기 때문에 IRQ 스케줄링을 하더라도 큰 효과를 기대하기가 어렵다.
	따라서 이러한 문제를 우선순위 지정을 통해 해결할 수 없고, 결국은 L-app과 T-app을 분리 된 코어에서 처리해야 할 것이다.
### NetChannel DESIGN
VNS는 application과 통신하는 interface 역할로, 기존의 네트워크 스택과는 다르게 application과 주고받는 데이터를 버퍼링하고, 나머지 패킷 프로세싱 파이프라인과 분리시키는 역할을 한다.
가장 아래의 NetDriver는 네트워크를 channel이라는 일반화 된 가상화를 통해 위쪽 레이어에 제공하게 되고, 이를 multi-queue 장치로 추상화 시킨다.
applicatioin과 channel을 분리함으로써 유연하고, 잘게 쪼개진 멀티플렉싱/디멀티플렉싱과 두 레이어에서 데이터를 스케줄링하는 것이 가능해졌다.
멀티플렉싱과 디멀티플렉싱은 NetScheduler 에서 이루어진다. 이 스케줄러는 pluggable이며, 동적인 스케일링이 가능하다.

##### 3.1 Virtual Network System(VNS) Layer
application의 수정없이 본 Netchannel을 적용하기 위해 virtual socket을 통해 POSIX socket interface를 지원한다. application은 주로 socket과 system call 혹은 io_uring을 통해 상호작용하게 된다.

###### Ensuring correctness of interface semantics
모든 가상 소켓은 내부적으로 Tx와 Rx 버퍼를 유지하고 있다. reliablity는 NetDriver layer의 channel으로 넘기고, VNS에서는 서로 다른 virtual sockets들에서 순서를 보장해야할 것이다. 여기서 생기는 문제는 기존의 TCP에서의 sequence number는 더 이상 유효하지 않다는 것이다. 따라서 이것을 해결하기 위해 sender side에서는 각 virtual socket의 data packet들에 대하여 VNS가 각각의 패킷을 나타내는 시퀀스 번호를 삽입하게 된다. 이는 section4에서 더 자세히 논의 될 것이다. 결국 receiver side의 VNS는 이 시퀀스 번호를 보고 OOO 처리를 하게 된다.

>그렇다면 NetChannel이 활성화되어 있는 시스템끼리만 작동이 되는 건가?
>그렇다면 NetChannel <-> 기존 network stack 끼리 동작은 안되는 건가?
###### Decoupling data copy from application threads
VNS는 코어당 worker threads를 유지하고 있다. 이것은 userspace와 kernel 간의 data copy를 병렬적으로 처리하기 위해 존재한다. 따라서 모든 코어를 사용할 수 있다는 장점이 있다.

##### 3.2 NetDriver Layer
###### Channel abstraction
NetDriver에서, 각각의 channel은 Tx/Rx queue들과 독립적인 네트워크 계층(TCP reliable funcs) 처리 파이프라인을 가지고 있다.  이 때, 각각의 queue들이 create(), destroy()를 통해 생성, 제거되고, enqueue(), dequeue()를 통해 데이터가 전송되고, 데이터를 수신할 수 있다. 앞의 두개는 connection-oriented인 연결에 사용하면 되고, connection-less인 경우 뒤의 enqueue(), dequeue()만으로 동작이 이루어진다.
###### Decoupled network layer processing
이러한 NetDriver의 channel들은 VNS의 virtual interfaces로부터 분리되었는데, 이러한 아키텍처를 선택하여, 각각의 application이 사용하는 소켓과 코어가 하던 네트워크 계층 처리를 분리시킬 수 있다는 장점이 있다. 따라서 얼마나 많은 application이 얼마나 많은 socket/core를 사용하던지 간에 독립적으로 여러 개의 channel을 생성하고 사용할 수 있다. 또한, 이는 동적으로 할당/해제 할 수 있으므로, channel의 load에 따라 dynamic하게 resource를 할당하고 사용할 수 있다.

###### Integrating new transport designs
NetDriver는 이제 multi-queue device의 추상이므로, 새로운 네트워크 프로토콜을 짜는 것은 새로운 device driver를 만드는 것과 동일해진다. 이는 즉, 소켓과 관련된 귀찮은 API들을 고려할 필요가 없다는 뜻이다.
###### Piggybacking on transport-level flow control
virtual socket의 Rx buffer의 오버플로우를 방지하기 위해, NetDriver는 기본적으로 piggybacks을 flow control에 적용하고 있다.
###### Alleviating HoL blocking
하나의 channel이 여러개의 virtual socket들에게 공유 될 수 있기 때문에, 하나의 virtual socket에서 발생한 문제가 같은 channel을 사용하는 다른 virtual socket들에게 까지 영향을 미칠 수 있다. 따라서 특정 application이 장기간 read를 하지 않아 virtual socket과 channel의 queue가 가득 차서 더 이상 사용하지 못하게 되는 문제가 발생한다.
이러한 문제를 해결하기 위해 virtual socket마다 response queue를 두게 되었다. 만약 virtual socket이 가득 찼다면 더 이상 transmit을 안하게 하면 되지만, channel queue에 남아있는 해당 virtual socket의 패킷을 response queue에 넣게 되는 것이다. 따라서 channel queue에 들어온 것은 언제든지 response queue에 들어가게 된다.
이때 response queue의 자원은 channel의 버퍼를 사용하게 하여 channel의 flow control이 response queue에 들어간 entry의 갯수가 증가할 때 작동하도록 하였다.
![[Pasted image 20241101101625.png]]

##### 3.3 NetScheduler Layer
NetScheduler는 3가지 주요 역할이 있다.
1) application data를 channel로 multiplexing 및 scheduling
2) host간의 channel의 갯수를 동적으로 조절함.
3) data copy 요청을 scheduling함.
NetScheduler의 커널 상에서 위치를 보았을 때, 다양한 정보를 활용할 수 있다는 장점이 있다.
또한 본 논문에서는 스케줄러는 제안하는게 아니라, 다양한 스케줄러를 적용시킬 수 있는 프레임워크를 제공하고자 한다.

###### Dynamic sceduling of application data to channels
application으로부터 데이터가 입력되었을 떄, NetScheduler는 스케줄링 정책을 통해 skb당 보낼 채널을 선택하게 된다. 이는 코어 간에 네트워크 계층 프로세싱을 스케일링할 수 있게 한다.
###### Dynamic scaling and placement of channels
NetScheduler는 channel을 동적으로 스케일링 할 수 있다. 이는 CPU 사용률과 같은 지표를 통해 스케줄링 기법을 만들어 낼 수 있을 것이다. 하나의 예시로, L-app과 T-app을 서로다른 채널에 분리 시키고, 이러한 채널들을 서로 다른 코어에 할당함으로써 isolation을 달성할 수 있다. 
###### Dynamic scheduling of data scopy requests
NetScheduler는 data copy를 할 때 virtual socket을 활용하여 여러 코어에 작업을 할당 함으로써 전체 CPU 사용량을 늘리고, bottleneck을 극복할 수 있었다.

### NetChannel IMPLEMENTATION
리눅스 커널 v5.6에서 구현을 하였고, 대부분의 코드들을 재사용 할 수 있도록 하였다.

###### Application interfaces
VNS에서, `IPPROTO_VIRTUAL_SOCK`이라는 flag를 추가하여 virtual socket을 구현하였다. 또한, Application에서는 setsockopt()이라는 함수를 통해 NetChannel과 관련 된 옵션들을 설정할 수 있다. 예를 들어, SO_APP_TYPE을 통해 L-app인지, T-app인지 설정할 수 있다.RPC interface 또한 비슷하게 설정된다.
###### Virtual socket connections
virtual socket interface에서 connection을 만드는데는 다음과 같은 과정이 진행된다. 먼저 client가 connect 시스템 콜을 통해 `connect`를 초기화하고, 그와 동시에 remote host의 listen socket은 connection request를 수락하고 새로운 소켓을 request마다 반환하게 된다. 이 때 virtual socket은 handshake를 `NCSYN` 와 `NCSYN_ACK`를 통해 하게 되는데, 이미 channel을 통해 reliability를 제공하고 있으므로, 2-way handshake로 충분하다.
###### NetChannel headers
virtual socket과 channel은 서로 다대다 관계를 유지할 수 있기 때문에, NetChannel은 각가의 패킷에 대하여 어떤 virtual socket이 맞는 건지 알아낼 수 있어야 한다.
따라서, NetChannel은 패킷 페이로드 위에 또 다른 헤더를 추가하게 되었다. 이 헤더는 3가지 구성요소로 이루어져있다.
1) virtual socket의 source/destination port num
2) virtual socket의 sequence number (*multiple channel을 사용할 때 reordering을 위하여*)
3) packet type (data packet과 control packet을 구분하기 위함)
이렇게 NetChannel header를 사용하게 되면 channel's header를 수정할 필요 없이 virtual socket을 사용할 수 있다.
###### Reducing page allocation overheads for DMA
본 구현에서는 각 NIC의 receive queue마다 dedicated page pool을 설정하였다. 이 때, 큰 page pool은 page allocation overhead를 줄일 수 있겠지만, DCA 효과때문에 L3 cache miss rate이 올라갈 수 있다. 따라서 본 논문에서는 256을 기본 page pool size로 하였다. 저자들은 이 값이 메모리 오버헤드를 줄이면서도 cache miss rate이 적은 합리적이면서도 충분하다는 것을 발견하였다.
>여기서 256이란 값은 휴리스틱하게 찾아진 값인가? 아니면 따로 공식이 존재하는건가?

NIC이 256개의 receive queue를 가지고 있더라도, 이 page pool을 유지하기 위한 메모리 오버헤드는 256 X 256 X 4KB = 256MB에 지나지 않는다.
이 것들은 최신 서버에서 충분히 무시할 만하다.
###### Scheduling policy
현재 NetScehduler에 구현된 스케줄링 정책은 round-robin이다. 이는 application to channel과 data copy requests to workers에 적용되어 있다. 또한 추가적으로, application to chaanel에서는 L-app과 T-app을 구분하기 위해 서로 같은 타입의 channel만 하나의 application에 할당하게 된다.
기존 channel/worker의 overloading을 방지하기 위해 queue 사용량이 특정 임계값을 넘으면 스케줄링에서 제외 시켰다.
이때 각각 2MB, 640KB라는 값이 임계값으로 가장 적당하다는 것을 섬세하고 간단한 분석을 통해 찾아내었다.

### NetChannel EVALUATION
먼저 실험환경의 셋업을 설명하고, 어떻게 오늘날의 리눅스 네트워크 스택의 한계를 줄일 수 있었는지 보여주며, 현재의 NetChannel prototype의 오버헤드를 보여주고, 실제 application에서의 효과적임을 보여주고, 마지막으로 Terabit ethernet으로의 스케일링 가능성을 보여주고자한다.
##### 5.1 Evaluation Setup
###### Hardware setup
하드웨어는 두개의 서버로 이루어져 있으며 100Gbps의 링크로 직접 연결되어 있다. 각각의 서버는 4개의 NUMA노드와 노드당 8개의 코어로 이루어져 있다.(Inter Xeon Gold 6234 3.3GHz CPU) 그리고 32KB/1MB/25MB L1/L2/L3 cache가 있으며, 384GB의 DRAM과 100Gbps NVIDIA Mellanox ConnectX-5 NIC을 달고 있다. 두 서버 모두 Ubuntu 20.04(kernel v5.6)으로 돌아가고 있으며, 기본값으로, TSO, GRO, Jumbo Frames(9KB), aRFS, Dynamically-Tuned Interrupt Moderation(DIM)을 켰다.
또한, 하이퍼쓰레딩과 IOMMU를 끄는데, 모두 성능을 최대화하기 위함이다. DCA(Intel DDIO)는 켜져있다.
###### Evaluated workloads
섹션 2에서 했듯이 T-app과 L-app을 적당히 만들었고, application-level processing을 최소화하였고, network stack이 bottleneck이 될 수 있게끔 하였다. 본 측정에서는 read/write 시스템 콜 밎 io_uring 두 시나리오 모두 고려하였다.
모든 실험에서 NIC이 달려있는 NUMA 노드의 코어만 사용하였다. 또한 실제 application으로 Redis와 SPDK를 사용하였다.
###### Performance metrics
throughput과 L-app의 P99.9 latency를 측정하게 된다.
또한 CPU efficiency와 오버헤드 이해를 위해 throughput-per-core 또한 측정하였다.
##### 5.2 New operating points
지금부터는 NetChannel이 어떻게 새로운 3개의 운영포인트를 가능케 하는지 보여줄 것이다. 시나리오는 섹션 2.2에서 사용한 것을 사용할 것이다.
###### Scalability for log flows
기존의 리눅스 네트워크 스택은 100Gbps saturate를 하지 못했지만, NetChannel은 100Gbps를 saturate할 수 있다는 것을 보여주었다. 그 이유로는 data copy worker를 두개를 쓸 수 있기 때문인데, 이 것은 기존 리눅스 네트워크 스택에서 이 시나리오에서의 bottleneck이였다. NetChannel은 하나의 channel에서 여러 개의 worker thread를 돌릴 수 있기 때문에 이러한 결과를 얻을 수 있었다. io_uring을 사용할 때도 마찬가지이다.
###### Scalability for short messages
섹션 2.2에서의 시나리오를 그대로 쓰되, 극한의 상황을 만들기 위해 TSO/GRO 및 Jumbo Frame을 껐다.
NetChannel은 하나의 virtual socket에서 여러개의 channel을 사용할 수 있기 때문에, 네트워크 계층 프로세싱을 동적으로 스케일링 할 수 있다. 실제 결과를 보면 channel의 갯수가 늘어날 때마다 대역폭이 상승하고 있음을 확인할 수 있다.
###### Enabling performance isolation
여기서는 8개의 T-app과 한 개의 L-app을 8 core에서 돌렸다. 이 때, 더이상 io_uring에 대하여 측정을 진행하지는 않았는데, 앞서 두 개의 시나리오에서 볼 수 있 듯이 성능 개선효과가 없었기 때문이다. 기존의 네트워크 스택에서는 L-app과 T-app은 처리과정 중에 서로 간섭이 가능하기 때문에 L-app의 레이턴시가 매우 낮아지는 문제를 겪고 있었다. 그러나 NetChannel을 사용하게 된다면, 심지어 같은 코어에서 처리되는 application이더라도 channel을 통해 virtual socket들을 분리하여 네트워크 계층 처리를 격리할 수 있다. 따라서 결과를 살펴보면, 레이턴시가 상당히 낮아진다는 것을 볼 수 있다.
##### 5.3 Understanding NetChannel Overheads
###### Overheads of emulating the Linux network stack
NetChannel을 도입함으로서 생기는 오버헤드를 이해하기 위해, 싱글 패킷 프로세싱 파이프라인을 emulate하였다. single application thread와 single channel thread를 사용하였다. 이러한 결과로 보았을 떄, NetChannel을 도입함으로써 약 7%의 성능 손실이 발생한다는 것을 알 수 있다. 이는 server-side의 core가 양쪽 시스템의 bottleneck임을 의미한다.
###### Overheads of scaling data copy processing
NetChannel의 scaling data copy processing에서 overhead를 알아보기 위해, 기존 리눅스에서는 3개의 별도의 connection에서 100Gbps를 만들었고, NetChannel은 2 data copy threads와 1 channel thread를 사용하였다. 여기서도 약 12% 정도의 성능 감소가 있었는데, 주요한 원인으로는 application buffer가 L1 캐시로 많이 올라와 있지 않아서 아직 hit ratio가 그렇게 높지 않기 때문이다. 따라서 data copy 동안 높은 L1 cache miss를 유발한다.
###### Overheads of scaling network layer processing
NetChannel에서 network layer processing을 scaling하는 과정에서 생기는 overhead를 알아보기 위해서 channel이 늘아날 때마다 throughput-per-core를 측정하였다. 채널의 갯수와 상관없이 코어당 쓰루풋은 같았고, 기존의 리눅스 스택과 비교하였을 때 아주 약간의 성능 감소만 있었다.
여기서 발생한 오버헤드의 경우, NetScheduler가 channel thread들을 깨우는 과정에서 발생하게 된다. 이는 특히 short message를 처리하고 sleep과 wake up이 반복적으로 일어나는 과정 속에서 더욱 부각되게 된다.
이러한 오버헤드는 NetScheduler layer에서 batching을 통해 줄일 수 있을 것이다.
###### Overheads of achieving performance isolation
L-app과 T-app이 동시에 실행중인 상황에서 NetChannel의 오버헤드를 관찰하기 위해 T-app의 throughput을 각 시나리오에서 측정하였다. 이때 NetChannel은 코어당 Thoughput 측면에서 12%정도의 성능감소를 보여주었다. 그러나 이러한 감소를 만회하는 Tail-latency의 개선을 확인할 수 있었다.
##### 5.4 Real-world applications with NetChannel
실제 사용되는 application들을 사용하여 그 결과를 보여주고 있고, 실제 성능이 개선되었음을 보여준다.
이 곳은 생략하고 넘어갈 것이다.
##### 5.5 netChannel with Terabit Ethernet
2channel과 3 data copy threads를 통하여 200Gbps saturate를 달성하였다. 여기서 특이한 점은 100Gbps saturate와는 다르게 하나의 channel로 200Gbps를 saturate할 수가 없다는 점이다. 그 이유로는 single core의 성능이 200Gbps를 감당할만한 network layer processing이 불가능하기 때문이다.

>그럼 실제로 하나의 channel 당 saturate되는 성능은 어느정도인가? IPC연관 지어서 그 속도를 이론적으로 계산해 낼 수 있나?