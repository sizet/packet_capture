#### �sĶ.
```
# �sĶ�{��.
make
# �M���sĶ���G.
make clean
```
#### ����{��.
```
packet_capture �Ѽ�...
  <-i �A�Ӻ��������W��>
    ��ť�������������ʥ].
    �Ҧp : -i eth0
  <-c �ɮ׸��|>
    ���ť�쪺�ʥ]�x�s�즹�ɮ� (pcap �榡).
    �Ҧp : -c packet.pcap
  [-p �ɮ׸��|]
    ��{����PID �x�s�즹�ɮ�.
    �Ҧp : -p /var/run/packet_capture.pid
```
#### �ϥΫH������{��.
```
SIGINT, SIGQUIT, SIGTERM
  ����{��.
SIGUSR1
  ��ܥثe��ť�쪺�ʥ]�ƥ�.
```
