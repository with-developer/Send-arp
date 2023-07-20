# Send ARP

- 강의: S-dev 네트워크 보안<br>
- 마감일: July 20, 2023<br>
- 상태: 완료<br>
- 유형: 과제

# Source Code

[https://github.com/with-developer/Send-arp](https://github.com/with-developer/Send-arp)

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
