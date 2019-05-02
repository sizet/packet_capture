#### 編譯.
```
# 編譯程式.
make
# 清除編譯結果.
make clean
```
#### 執行程式.
```
packet_capture 參數...
  <-i 乙太網路介面名稱>
    監聽此網路介面的封包.
    例如 : -i eth0
  <-c 檔案路徑>
    把監聽到的封包儲存到此檔案 (pcap 格式).
    例如 : -c packet.pcap
  [-p 檔案路徑]
    把程式的PID 儲存到此檔案.
    例如 : -p /var/run/packet_capture.pid
```
#### 使用信號控制程式.
```
SIGINT, SIGQUIT, SIGTERM
  停止程式.
SIGUSR1
  顯示目前監聽到的封包數目.
```
