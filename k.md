timer 부분 알아오기
tcp 하나에 하나의 타이머
하드웨어 타이머를 쓰는가?
tcp flow가 많아지면 타이머 스케줄링이 많아진다
아마 cpu안의 타이머일듯 주기적인 인터럽트를 건다.
tcp timeout 과 cpu timer의 관련
하드웨어 안쓰는 경우는 어떻게되나

TX
netdev 변수로 device 정보 저장
netdev 정보가 언제 가장 먼저 등장하는가
routing 을 위해 ip 에서 먼저 등장할듯?

ops->ndo_start_start_xmit()

iperf verson check
retranmission 도 bw 에 포함하는가
ftrace로 trace 비교해보기
mellanox 40gps, no ice driver, driver mlx4


