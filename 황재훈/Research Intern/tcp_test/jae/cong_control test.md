__CUBIC mtu 1500__
cubic (1 connection) mtu 1500
![[Pasted image 20241106211743.png]]
![[Pasted image 20241107202444.png]]

cubic (10 connection) mtu 1500
![[Pasted image 20241106212648.png]]
![[Pasted image 20241107202509.png]]
![[Pasted image 20241112185219.png]]
pkt loss 가 없어서 cwnd 가 지속적으로 늘어난다. 

cubic (30 connection) mtu 1500
![[Pasted image 20241106212221.png]]
![[Pasted image 20241107202532.png]]

__CUBIC mtu 100__
cubic (1 connection) mtu 100
iperf3 -c 40.0.0.3 -t 30 > cubic_1con_100mtu
![[Pasted image 20241106214810.png]]
![[Pasted image 20241107201433.png]]

cubic (10 connection) mtu 100
iperf3 -c 40.0.0.3 -t 30 -P 10 > cubic_10con_100mtu
![[Pasted image 20241106215005.png]]
![[Pasted image 20241107201459.png]]

cubic (30 connection) mtu 100
iperf3 -c 40.0.0.3 -t 30 -P 30 > cubic_30con_100mtu
![[Pasted image 20241106215036.png]]
![[Pasted image 20241107201527.png]]

__BBR mtu 100__
bbr (1 connection) mtu 100
iperf3 -c 40.0.0.3 -t 30 > bbr_1con_100mtu 
![[Pasted image 20241106215820.png]]
![[Pasted image 20241107173756.png]]

bbr (10 connection) mtu 100
iperf3 -c 40.0.0.3 -t 30 -P 10 > bbr_10con_100mtu  
![[Pasted image 20241106215954.png]]
![[Pasted image 20241107173818.png]]

bbr (30 connection) mtu 100
iperf3 -c 40.0.0.3 -t 30 -P 30 > bbr_30con_100mtu   
![[Pasted image 20241106220012.png]]
![[Pasted image 20241107174041.png]]

__BBR mtu 1500__
bbr (1 connection) mtu 1500
iperf3 -c 40.0.0.3 -t 30 > bbr_1con_1500mtu
![[Pasted image 20241106220820.png]]
![[Pasted image 20241107173319.png]]

bbr (10 connection) mtu 1500
iperf3 -c 40.0.0.3 -t 30 -P 10 > bbr_10con_1500mtu
![[Pasted image 20241106220852.png]]
![[Pasted image 20241107173351.png]]

bbr (30 connection) mtu 1500
iperf3 -c 40.0.0.3 -t 30 -P 30 > bbr_30con_1500mtu
![[Pasted image 20241106220917.png]]
![[Pasted image 20241107173413.png]]