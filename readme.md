# Send ARP

- 강의: S-dev 네트워크 보안<br>
- 마감일: July 20, 2023<br>
- 상태: 완료<br>
- 유형: 과제

# 목차
[Task](#task)<br>
[ㄴDetail](#detail)<br>
[Source code](#source-code)<br>
[Code Reviw Feedback FROM gilgil mentor](#code-review-feedback-from-gilgil-Mentor)<br>
[Result](#result)<br><br>


# Task
```
Sender(Victim)의 ARP table을 변조하라.
```

### Detail

- Sender는 보통 Victim이라고도 함.
- Target은 일반적으로 gateway임.
- Sender와 Target은 하나만 있는 게 아니라 여러개의 (Sender, Target) 조합을 처리할 수 있도록 한다.
- 구글링을 통해서 ARP header의 구조(각 필드의 의미)를 익힌다.
- pcap_sendpacket 함수를 이용해서 User defined buffer를 packet으로 전송하는 방법을 익힌다.
- Attacker(자신) Mac 주소 값를 알아 내는 방법은 구글링을 통해서 코드를 베껴 와도 된다(반드시 interface 이름을 입력값으로해서 Mac을 알아내도록 한다).
- ARP infection packet 구성에 필요한 Sender의 Mac 주소 정보는 프로그램 레벨에서 자동으로(정상적인 ARP request를 날리고 그 ARP reply를 받아서) 알아 오도록 코딩한다.
- 최종적으로 상대방을 감염시킬 수 있도록 Ethernet header와 ARP header를 구성하여 ARP infection packet을 보내고 Sender에서 바라 보는 Target의 ARP table이 변조되는 것을 확인해 본다(arp -an).
- Attacker와 Victim(Sender), Target은 물리적으로 다른 호스트로 테스트할 것(하나의 가상 환경에서 여러개 띄워 테스트하지 말 것).
- Attacker가 Guest OS인 경우 네트워크를 bridge mode로 만들어 테스트할 것.
- Victim(Sender)은 자신의 스마트폰 혹은 여분의 PC나 노트북으로 테스트하거나, 다른 사람의 Host인 경우 허락을 맡고 테스트할 것.
- 감염 성공 여부는 Victim에서 ARP 테이블 변조 여부를 확인하거나, Victim에서 외부 ping을 실행한 상태(-t option을 주면 계속해서 ping이 나감)에서 ping 패킷이 Attacker의 Wireshark에서 잡히면 성공하는 것임.
- 패킷을 전송(pcap_sendpacket)만 할 때에는 "pcap_open_live(dev, 0, 0, 0, errbuf)" 이렇게 줘도 되지만, 패킷을 수신(pcap_next_ex)을 하려면 숫자 인자를 0으로 채워서는 안됨. 과제를 수행할 때 "pcap_open_live(dev, BUFSIZ, 1, 1, errbuf)"로 수정해서 작업을 할 것.
- 구조체는 libnet에 있는 헤더와 send-arp-test에 있는 헤더를 섞어서 사용하지 않는다(libnet 구조체만 사용하거나 send-arp-test에 있는 구조체만 사용하거나, 아니면 자신이 만든 구조체를 사용하거나).

# Source Code

[https://github.com/with-developer/Send-arp](https://github.com/with-developer/Send-arp)

# Code Review Feedback FROM gilgil Mentor
- 현재 코드에서 Sender IP, Target IP를 String 형식으로 입력받고, 프로세스 내부에서 연산할 때 대부분 string으로 처리를 합니다. (strcmp 등)
- 프로세스 내부에서 연산을 할 때, Capture한 Packet의 IP 혹은 MAC을 string으로 변환하는 작업이 많이 일어나기 때문에, 처음 Sender IP, Target IP를 입력받았을 때 이를 바로 byte 단위로 변환하여 연산하면 코드가 더 효율적일 것이라는 피드백을 해주셨습니다.

# Result

> 정상적으로 공격이 완료되었을 때
> 
> 
> ![Untitled](https://concise-egg-c3d.notion.site/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fb6b2664b-8804-493b-bf4f-34bb638cd5ad%2FUntitled.png?id=50d4ba0a-f338-4a7b-a819-bc59ce286d89&table=block&spaceId=cdedcb90-4171-4218-866c-2193f2353645&width=960&userId=&cache=v2)
> 

> 시간이 지나도 ARP Reply 패킷을 받을 수 없을 때
> 
> 
> ![Untitled](https://concise-egg-c3d.notion.site/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F51ef6318-5bdd-4eb9-a9a7-f4710da581d9%2FUntitled.png?id=fb22a642-8b06-4dc4-b39c-06c4cab9c49a&table=block&spaceId=cdedcb90-4171-4218-866c-2193f2353645&width=950&userId=&cache=v2)
> 

> Sender IP의 mac address를 구하기 위해 전송한 Request 패킷
> 
> 
> ![Untitled](https://concise-egg-c3d.notion.site/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fd0b7b6f3-6aad-4e1e-bc5c-ba096985072d%2FUntitled.png?id=a23175d2-9e33-468c-be0b-53815433623b&table=block&spaceId=cdedcb90-4171-4218-866c-2193f2353645&width=2000&userId=&cache=v2)
> 

> Sender IP의 mac address를 구하기 위해 전송 받은 Reply 패킷
> 
> 
> ![Untitled](https://concise-egg-c3d.notion.site/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F06071c2c-8dbf-4c18-b0e6-bb825118b432%2FUntitled.png?id=5a49c109-66f2-4221-b5ba-782aa55af915&table=block&spaceId=cdedcb90-4171-4218-866c-2193f2353645&width=2000&userId=&cache=v2)
> 

> Target IP의 mac address를 구하기 위해 전송한 Request 패킷
> 
> 
> ![Untitled](https://concise-egg-c3d.notion.site/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fac58c268-97c3-49e1-a09a-9cc3f8f344c2%2FUntitled.png?id=516cfc1e-c704-4e68-ba88-8935e60b6521&table=block&spaceId=cdedcb90-4171-4218-866c-2193f2353645&width=2000&userId=&cache=v2)
> 

> Target IP의 mac address를 구하기 위해 전송받은 Reply 패킷
> 
> 
> ![Untitled](https://concise-egg-c3d.notion.site/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2Fa1676c6e-a7c1-4c8f-8a7c-e0811a11c94e%2FUntitled.png?id=91a1901f-c27d-43fc-a1e9-f13cec24720d&table=block&spaceId=cdedcb90-4171-4218-866c-2193f2353645&width=2000&userId=&cache=v2)
> 

> ARP Spoof 패킷을 Sender에게 Reply
> 
> 
> ![Untitled](https://concise-egg-c3d.notion.site/image/https%3A%2F%2Fs3-us-west-2.amazonaws.com%2Fsecure.notion-static.com%2F3914694b-c3b8-4c40-9643-7fe36f0bb099%2FUntitled.png?id=5742cc44-3b32-4d6b-876d-e959fb584668&table=block&spaceId=cdedcb90-4171-4218-866c-2193f2353645&width=2000&userId=&cache=v2)
>
