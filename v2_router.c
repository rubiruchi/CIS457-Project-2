#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <time.h>

///////////
//STRUCTS//
///////////

//STRUCT 
struct packet {
	int open;	     //1 yes, 0 no.
	char buf[1500];	     //The packet. 
	uint32_t expected_ip;//Expected ARP sender ip.
	int sockfd;	     //The socket we received it on.
	double time_stamp;   //Time in the system clock that we received the packet.
};

//STRUCT FOR FORWARDING TABLE.
struct fwd_atr{
	int i_num;
	int sockfd;
	int prefix;
	uint32_t ip;
	uint32_t hop;
};

//STRUCT FOR INTERFACE LIST.
struct interface{
	int sockfd;
	u_int8_t mac[6];
	uint32_t ip;
};

//ICMP HEADER
struct icmp_hdr{
	u_int8_t type;
	u_int8_t code;
	uint16_t check_sum;
	uint16_t id;
	uint16_t seq_num;
	u_int8_t t_stamp[8];
	u_int8_t data[48];
};

/////////////
//FUNCTIONS//
/////////////

//CHECK SUM
u_short cksum(u_short * buf, int count){
	register u_long sum = 0;
	while (count -- ){
		sum += *buf++;
		if(sum & 0xFFFF0000){
			sum &= 0xFFFF;
			sum++;
		}
	}
	return ~(sum & 0xFFFF);
}

//SEND A ICMP TIME EXCEEDED, THIS HAPPENS IF TTL BECOMES 0 AFTER DEC					
int icmp_error_msg(char * buf, int sockfd, int type, int code, struct interface ** if_list){

	//HEADER STRUCTS
	struct iphdr iph;					//IP header.
	struct icmp_hdr icmp;					//ICMP header.
	struct ether_header eh;					//ETHERNET header.

	/////////////////////////////////////////
	//GRAB HEADERS AND REFORMAT FOR SENDING//
	/////////////////////////////////////////
	
	//ETHER HEADER
	memcpy(&eh,&buf[0],14);					//Grab ETHERNET header.
	uint8_t tmp_eth[6];					//Tmp var. 	
	memcpy(tmp_eth,eh.ether_shost,6);			//Grab src. 
	memcpy(eh.ether_shost,eh.ether_dhost,6);		//Make dst the src.
	memcpy(eh.ether_dhost,tmp_eth,6);			//Make src the dst.
	
	//IP HEADER
	memcpy(&iph,&buf[14],20);				//Grab the IP header.
	uint32_t tmp_ip;					//Tmp var.
	memcpy(&tmp_ip,&iph.saddr,4);				//Grab src.
	memcpy(&iph.saddr,&iph.daddr,4);			//Make the src the sender dst.
	memcpy(&iph.daddr,&tmp_ip,4);				//Make the dst the sender src.

	//ICMP HEADER
	memcpy(&icmp,&buf[34],64);				//Grab the ICMP header.
	icmp.type = type;					//Set the type.
	icmp.code = code;					//Set the code.
		
	//RECALC CHECKSUM               
	unsigned short chk_sum_buf[32];        		        //Create a buf for the check sum.
	icmp.check_sum = 0x0000;				//Set check sum to zero before the calculation.
	memcpy(chk_sum_buf,&icmp,64);                    	//Copy all of ICMP packet into buffer.
	unsigned short new_cksum = cksum(chk_sum_buf,32);	//Calc the check sum.
	icmp.check_sum = new_cksum;                      	//Put in the new check sum;
	                                
	//PRINT PROGRAM
	printf("\n~~~~~~ICMP ERROR CONTENTS~~~~~~\n");
        printf("MAC SRC %s\n", ether_ntoa((struct ether_addr*)eh.ether_shost));
        printf("MAC DST %s\n", ether_ntoa((struct ether_addr*)eh.ether_dhost));
        printf("IP SRC %s\n", inet_ntoa(*(struct in_addr*)&iph.saddr));
        printf("IP DST %s\n", inet_ntoa(*(struct in_addr*)&iph.daddr));
        printf("TYPE %d\n", icmp.type);

	//BUILD PACKAGE
	unsigned char packet[98];				//The packet.
	memcpy(&packet[0],&eh,14);				//Copy in ETHERNET header.
	memcpy(&packet[14],&iph,20);				//Copy in the IP header.
	memcpy(&packet[34],&icmp,64);				//Copy in the ICMP header

	//SEND BACK TO SENDER
	send(sockfd,packet,sizeof(packet),0);

	//PRINT PROGRAM
	if(type == 11)
		printf("\nSent ICMP TIME X on socket %d\n", sockfd);
	if(type == 3 && code == 0)
		printf("\nSent ICMP NET UNRECHABLE on socket %d\n", sockfd);
	if(type == 3 && code == 1)
		printf("\nSent ICMP HOST UNREACHABLE on socket %d\n", sockfd);

	return 0;	
}

//DO CHECKSUM CALC, VERIFY THAT THE PACKET IS OKAY			
//If incorrect drop check sum.
int verify_chksum(char * buf){
		
	//HEADER STRUCTS
	struct iphdr iph;

	//COPY IN IP HEADER
	memcpy(&iph,&buf[14],20);

	//GRAB OLD CHECK SUM
	unsigned short old_check = iph.check;
	
	//CALC NEW CHECK SUM
	iph.check = 0x0000;				       //Set check sum field to zero to do a proper checksum.	
	unsigned short chk_sum_buf[10];   		       //Create a buf for the check sum.
	memcpy(chk_sum_buf,&iph,20);       		       //Copy all of ICMP packet into buffer.
	unsigned short new_check = cksum(chk_sum_buf,10);      //Calc the check sum.

	printf("\nOLD CHKSUM %x\nNEW CKSUM %x\n", old_check, new_check);
	
	//COMPARE OLD AND NEW CHECK SUM
	if(new_check == old_check){	//IF THEY ARE THE SAME...
		puts("\nCHECKSUM WORKS!\n");
		return 1;		//RETURN 1.
	}else{				//ELSE...
		puts("\nCHECKSUM DOES NOT WORK :(\n");
		return 0;		//RETURN 0.
	}
}	

//LOOP THROUGH PACKET LIST						      			
void check_timestamp(struct packet ** packet_list, struct interface ** if_list){
	int i;
	double sys_time = (( (double) clock() ) / CLOCKS_PER_SEC ) * 1000;		
	for(i=0; i<1000; i++){
		//IF PACKET HAS BEEN SITTING FOR MORE THAT 100 MS
		//printf("\nCHEKC TIME STAMP CALC %f\n",  sys_time);
		if(packet_list[i]->open == 0 && sys_time - packet_list[i]->time_stamp > 100){
			//PRINT PROGRAM
			puts("\nWE GOT A STALE PACKET D:\n");
		
			//SEND OUT ICMP HOST UNREACHABLE MSG
			icmp_error_msg(packet_list[i]->buf,packet_list[i]->sockfd,3,1,if_list);
		
			//OPEN THIS SPOT IN THE PACKET LIST
			packet_list[i]->open = 1;
		}
	}
}

//DEC TTL DEC, AND RETURN IT						
//IF TTL IS 0, DROP PACKET AND SEND ICMP TIME EXCEEDED
//ELSE REDO CHECKSUM
int do_ttl(char * buf){
	
	//HEADER STRUCTS
	struct iphdr iph;
	
	//GRAB IP HEADER
	memcpy(&iph,&buf[14],20);
	
	//DEC TTL
	int rtn = iph.ttl -= 1;

	//RECOMPUTE CHECKSUM
	unsigned short chk_sum_buf[10];			 //Create a buf for the check sum.
	iph.check = 0xFFFF;				 //Zero out the old check sum.
	memcpy(chk_sum_buf,&iph,20);			 //Copy all of ICMP packet into buffer.
	unsigned short new_cksum = cksum(chk_sum_buf,10);//Calc the check sum.
	iph.check = new_cksum;				 //Copy in the new check sum.

	//COPY DEC TTL BACK INTO PACKET
	memcpy(&buf[14],&iph,20);	

	//RETURN TTL AFTER DEC
	return rtn;
}

//READ FILE
void readFile(char * filename, struct fwd_atr ** fwd_table){
	//OPEN FILE AND READ ONE LINE
	FILE * file = fopen(filename,"r");
	int index = 0;
	char buffer[1024];

	while(fgets(buffer,1024,file) != NULL){
		char prefix[16];
		char i_name[16];
		char hop[16];
		char ip[9];
		
		printf("%s",buffer);
		sscanf(buffer,"%s %s %s",prefix,hop,i_name);

		//GET THE INTERFACE NUMBER
		int len = strlen(i_name);
		fwd_table[index]->i_num = atoi(&i_name[len-1]);
		
		//PUT IP INTO THE TABLE
		len = strlen(prefix);
		memcpy(ip,&prefix[0],8);
		ip[8] = '\0';
		fwd_table[index]->ip = inet_addr(ip);

		//PUT PREFIX INTO FWD TABLE
		fwd_table[index]->prefix = atoi(&prefix[len-2]);
		
		//PUT HOP INTO THE TABLE
		if((len = strlen(hop)) > 2)
			fwd_table[index]->hop = inet_addr(hop);
		else
			fwd_table[index]->hop = 0;
		
		//INCREASE INDEX AND FLUSH THE BUFFER
		index++;
		bzero(buffer,1024);
	}	
	//CLOSE FILE
	fclose(file);
}

//USED TO FORWARD A CACHED PACKET THAT IS NOT ON ONE OF OUR INTERFACES.
//Used if we get a arp reply, then we know we can fwd a packet 
void fwd_packet(char * buf, struct packet ** packet_list, int sockfd){	
	//STRUCTS FOR EXTRACTING ARP REQUEST.
	struct ether_arp ah;	//Arp header.

	//STRUCTS FOR BUILDING PACKET TO BE SENT.								
	struct ether_header eh;	//Ethernet header.
	struct iphdr iph;	//IP header.
	struct icmp_hdr icmp;	//ICMP header.

	//GRAB ARP HEADER FROM BUFFER
	memcpy(&ah,&buf[14],28);

	//GRAB SENDER IP FROM ARP HEADER
	uint32_t sender_ip;
	memcpy(&sender_ip,ah.arp_spa,4);
	
	//FIND THE PACKET TO FWD 
	int i;
	for(i=0; i<100; i++){
		if(packet_list[i]->open == 0)//If there is a packet waiting to be sent here
			if(memcmp(&packet_list[i]->expected_ip,&sender_ip,4) == 0){//If this is the packet we are looking to send
				//////////////
				//FWD PACKET//	
				//////////////
			
				/////////////////////////////	
				//CONSTRUCT ETHERNET HEADER//
				/////////////////////////////
				memcpy(eh.ether_dhost,ah.arp_sha,6);	//Set ETHERNET dst.
				memcpy(eh.ether_shost,ah.arp_tha,6);	//Set ETHERNET src.		
				eh.ether_type = htons(0x0800);		//Set ETHRENET type to IP.

				///////////////////////
				//CONSTRUCT IP HEADER//
				///////////////////////
				memcpy(&iph,&packet_list[i]->buf[14],20);	//Grab the old IP header cus I am a lazy POS.

				/////////////////////////
				//CONSTRUCT ICMP HEADER//
				/////////////////////////
				memcpy(&icmp,&packet_list[i]->buf[34],64);
				
				////////////////
				//BUILD PACKET//
				////////////////
				unsigned char pkt[98];		//The packet.
				memcpy(&pkt[0],&eh,14);		//Copy in ETHERNET header.
				memcpy(&pkt[14],&iph,20);	//Copy in the IP header.
				memcpy(&pkt[34],&icmp,64);	//Copy in the ICMP header.
								
				//PRINT PROGRAM
			        printf("\n~~~~~~ECHO REQUEST CONTENTS~~~~~~\n");
			        printf("MAC SRC %s\n", ether_ntoa((struct ether_addr*)eh.ether_shost));
       		          	printf("MAC DST %s\n", ether_ntoa((struct ether_addr*)eh.ether_dhost));
        			printf("IP SRC %s\n", inet_ntoa(*(struct in_addr*)&iph.saddr));
        			printf("IP DST %s\n", inet_ntoa(*(struct in_addr*)&iph.daddr));
       				printf("TYPE %d\n", icmp.type);

				///////////////
				//SEND PACKET//
				///////////////
				send(sockfd,pkt,sizeof(pkt),0);	
				
				//REOPEN PACKET IN PACKET LIST 
				packet_list[i]->open = 1;
			}
	}
}

//USED TO BUILD A ARP REQUEST.
//used if we have a packet that is not for one of our interfaces.
//send out request to he hop.
//store the packer in the packet list.
void arp_request(char * buf, int idx, struct fwd_atr ** fwd_table, struct interface ** if_list, struct packet ** packet_list, int sockfd){					

	//STRUCTS USED TO BUILD ARP REQUEST.
	struct ether_header eh;
	struct ether_arp ah;
	struct iphdr iph;

	//GRAB PACKET IP HEADER.
	memcpy(&iph,&buf[14],20);

	////////////////////////
	//BUILD THE ARP HEADER//
	////////////////////////
	ah.ea_hdr.ar_hrd = htons(1); 		     	  //Set hardware format to ethernet.
	ah.ea_hdr.ar_pro = htons(0x0800);	     	  //Set protocol format to IP.
	ah.ea_hdr.ar_hln = 6;   	  	     	  //Set hardware length to 6 bytes.
	ah.ea_hdr.ar_pln = 4;	  		     	  //Set protocol length to 4 bytes.
	ah.ea_hdr.ar_op = htons(ARPOP_REQUEST);      	  //Set the ARP operation to request	
								
	int i_num = fwd_table[idx]->i_num;	     	  //Grab the index of the interface we are sending on.
	memcpy(&ah.arp_sha,if_list[i_num]->mac,6);   	  //Set the sender MAC address (MAC of the interface we are sending on).			
	memcpy(&ah.arp_spa,&if_list[i_num]->ip,4);   	  //Set the sender IP address 
								
	u_int8_t tmp[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};//Broadcast destination.
	memcpy(&ah.arp_tha,tmp,6);	                  //Set the target hardware address(FF:FF:FF:FF:FF:FF).
								
	/////////////////////////////////////////////////////////
	//CHECK IF WE ARE SENDING A PACKET ON A DIFFRENT ROUTER//
	/////////////////////////////////////////////////////////
	uint32_t blank_ip_addr = inet_addr("0.0.0.0");
	printf("\nNEXT HOP : %s\n", inet_ntoa(*(struct in_addr *)&fwd_table[idx]->hop));
	printf("\nBLANK ADDR : %s\n", inet_ntoa(*(struct in_addr *)&blank_ip_addr));

	if(memcmp(&fwd_table[idx]->hop,&blank_ip_addr,4) != 0){	     	//If the fwd table prefix has a hop (Next closest router)...
		puts("\nWE ARE SENDING AN ARP TO THE NEXT HOP\n");	//Print program.
		memcpy(&ah.arp_tpa,&fwd_table[idx]->hop,4);   		//Set the target IP address. (The hop field in the fwd table).
	}else{						      		//Otherwise...
		puts("\nWE ARE SENDING AN ARP ON THIS HOP\n");		//Print program.
		memcpy(&ah.arp_tpa,&iph.daddr,6);	      		//Set the target IP address. (The target IP in the packet).
	}	

	/////////////////////////////
	//BUILD THE ETHERNET HEADER//
	/////////////////////////////
	memcpy(eh.ether_shost,if_list[i_num]->mac,6);	     //Set the source mac address(The MAC of the interace it is sent on).
	memcpy(eh.ether_dhost,tmp,6);			     //Set the destination mac address(FF:FF:FF:FF:FF:FF).
	eh.ether_type = htons(0x0806);			     //Set the ETHERNET type to ARP. 

	//PRINT PROGRAM
	printf("~~~~~CONTENTS OF ARP REQUEST~~~~~\n");
        printf("ARP opcode : %d\n", ntohs(ah.ea_hdr.ar_op));
        printf("Sender MAC address : %s\n", ether_ntoa((struct ether_addr *)&ah.arp_sha));
        printf("Sender IP adress : %s\n", inet_ntoa(*(struct in_addr*)&ah.arp_spa));
        printf("Target MAC addr: %s\n", ether_ntoa((struct ether_addr *)&ah.arp_tha));
        printf("Target IP addr: %s\n", inet_ntoa(*(struct in_addr*)&ah.arp_tpa));
        printf("~~~~~ETHER HEADER CONTENTS~~~~~\n");
        printf("SRC MAC ADDR : %s\n", ether_ntoa((struct ether_addr *)&eh.ether_shost));
        printf("DST MAC ADDR : %s\n", ether_ntoa((struct ether_addr *)&eh.ether_dhost));

	///////////////////////
	//COPY INTO A REQUEST//
	///////////////////////
	unsigned char request[42];		//The response.
	memcpy(&request[0],&eh,14);		//Copy in the ethernet header.
	memcpy(&request[14],&ah,28);		//Copy in the arp header.

	////////////////////
	//SEND ARP REQUEST//
	////////////////////
	send(if_list[i_num]->sockfd,request,sizeof(request),0);
	
	/////////////////////////////
	//SAVE THE PACKET FOR LATER//
	/////////////////////////////
	
	//LOOP THROUGH PACKET LIST
	int i; 
	for(i=0; i<100; i++){
		//IF A SECTION IS OPEN FILL IT UP
		if(packet_list[i]->open = 1){
			memcpy(packet_list[i]->buf,&buf[0],1500);		//Copy in the packet buffer.
			memcpy(&packet_list[i]->expected_ip,&ah.arp_tpa,4);	//Copy in the expected IP addr (The dst IP in the ARP request).		
			packet_list[i]->open = 0;				//Set packet to not open.
			packet_list[i]->sockfd = sockfd;			//Grab the socket the packet was received on.
			packet_list[i]->time_stamp = ( ((double) clock())/CLOCKS_PER_SEC ) * 1000;	
			printf("\ntimestamp : %f\n", packet_list[i]->time_stamp);	
			break;							//GET.OUT.
		}
	}	
}

//CHECK IF THE PACKET IS FOR ONE OF OUR INTERFACES.
//returns index of the interface in if_list, or -1 of not found
int if_lookup(struct interface ** if_list, char * buf, int type){
	u_int32_t target_ip;
	
	//THIS IS A ARP PACKET	
	if(type == 0){
		struct ether_arp ah;
		memcpy(&ah,&buf[14],28);
		memcpy(&target_ip,ah.arp_tpa,4);
	}

	//THIS IS A IP PACKET
	if(type == 1){
		struct iphdr iph;
		memcpy(&iph,&buf[14],20);
		target_ip = iph.daddr;
		//inet_ntoa(*(struct in_addr*)&ah.arp_spa)
	}
	
	int i;
        for(i=0; i<5; i++){
                if(memcmp(&target_ip,&if_list[i]->ip,4) == 0){	
                        return i;	//return the index of the interface.
                }
        }

	return -1;
}

//LOOK UP WHERE TO FORWARD THE PACKET
//returns index of interface, or -1 if it is not for us.
int fwd_lookup(struct fwd_atr ** fwd_table, char * buf){	
	//GRAB THE TARGET IP ADDRESS FROM THE PACKET
	u_int32_t target_ip;
	struct iphdr iph;
	memcpy(&iph,&buf[14],20);
	memcpy(&target_ip,&iph.daddr,4);
	
	puts("\nDOING A FWD TABLE LOOKUP\n");
	
	//ETHERNET INDEXES
	int index_16 = -1;
	int index_24 = -1;

	//LOOP THROUGH FWD TABLE
	int i;
	for(i=0; i<5; i++){
		if(fwd_table[i]->prefix == 24){
			//MODIFY IPS TO COMPARE PREFIXES
			u_int32_t tmp1 = (target_ip & 0x00FFFFFF);
			u_int32_t tmp2 = (fwd_table[i]->ip & 0x00FFFFFF);
			
			//PRINT PROGRAM				
			//printf("\nTarget IP : %s\n", inet_ntoa(*(struct in_addr *)&tmp1));
			//printf("\nPrefix IP : %s\n", inet_ntoa(*(struct in_addr *)&tmp2));
				
			//COMPARE
			if(memcmp(&tmp1,&tmp2,4)==0){
				printf("\nFOUND MATCH ON ETH %d\n", fwd_table[i]->i_num);
				return i;//return index of interface
			}
		}
		if(fwd_table[i]->prefix == 16){
			//MODIFY IPS TO COMPARE PREFIXES
			u_int32_t tmp1 = (target_ip & 0x0000FFFF);
			u_int32_t tmp2 = (fwd_table[i]->ip & 0x0000FFFF);
			
			//PRINT PROGRAM
			//printf("\nTarget IP : %s\n", inet_ntoa(*(struct in_addr *)&tmp1));
			//printf("\nPrefix IP : %s\n", inet_ntoa(*(struct in_addr *)&tmp2));
				
			//COMPARE
			if(memcmp(&tmp1,&tmp2,4)==0){
				printf("\nFOUND MATCH ON ETH %d\n", fwd_table[i]->i_num);
				return i;//return index interface
			}
		}
	}
		puts("\nNO MATCH :(\n");
		return -1; 	//ELSE RETURN -1
}

//BUILD AND SEND OUT ARP RESPONSE TO A ARP REQUEST 
void arp_response(char * buf, struct interface ** if_list, int idx, int sockfd){

	//PRINT PROGRAM
	printf("\nsockfd: %d\n", sockfd);

	u_int8_t sender_mac[7];		//MAC addr of who sent the arp
	u_int8_t sender_ip[5];		//IP addr of who sent the arp
	
	//////////////////
	//SET UP HEADERS//
	//////////////////
	struct ether_header eh;	//Ether header
	memcpy(&eh,&buf[0],14);
	
	struct ether_arp ah;	//Arp header
	memcpy(&ah,&buf[14],28);

	//PRINT PROGRAM
	printf("~~~~~CONTENTS OF ARP REQUEST~~~~~\n");
        printf("ARP opcode : %d\n", ntohs(ah.ea_hdr.ar_op));
        printf("Sender MAC address : %s\n", ether_ntoa((struct ether_addr *)&ah.arp_sha));
        printf("Sender IP adress : %s\n", inet_ntoa(*(struct in_addr*)&ah.arp_spa));
        printf("Target MAC addr: %s\n", ether_ntoa((struct ether_addr *)&ah.arp_tha));
        printf("Target IP addr: %s\n", inet_ntoa(*(struct in_addr*)&ah.arp_tpa));
        printf("~~~~~ETHER HEADER CONTENTS~~~~~\n");
        printf("SRC MAC ADDR : %s\n", ether_ntoa((struct ether_addr *)&eh.ether_shost));
        printf("DST MAC ADDR : %s\n", ether_ntoa((struct ether_addr *)&eh.ether_dhost));

	/////////////////////////////////ARP HEADER/////////////////////////////
	//MAKE IT A RESPONSE						      //
	////////////////////////////////////////////////////////////////////////
		
	//MAKE THIS A RESPONSE
	ah.ea_hdr.ar_op = htons(ARPOP_REPLY);
		
	//SET SENDER MAC
	memcpy(sender_mac,ah.arp_sha,6);	//GRAB SENDER MAC FOR LATER
	sender_mac[6] = '\0';
	memcpy(ah.arp_sha,if_list[idx]->mac,6);	//COPY IN INTERFACE MAC

	//SET SENDER IP
	memcpy(sender_ip,ah.arp_spa,4);	//GRAB SENDER IP FOR LATER
	sender_ip[4] = '\0';
	memcpy(ah.arp_spa,&if_list[idx]->ip,4);	//COPY IN INTERFACE IP

	//TARGET MAC BECOMES THE SENDER MAC		
	memcpy(ah.arp_tha,sender_mac,6);

	//TARGET IP BECOMES THE SENDER IP		
	memcpy(ah.arp_tpa,sender_ip,4);
		
	///////////////////////////////////ETHER HEADER////////////////////////////
	memcpy(&eh.ether_shost,if_list[idx]->mac,6);	
	memcpy(&eh.ether_dhost,sender_mac,6);
	
	u_int8_t reply[43];

	//COPY HEADERS BACK IN
	memcpy(&reply[0],&eh,14);//Copy in ether header.
	memcpy(&reply[14],&ah,28);//Copy in arp header.
	reply[42] = '\0';

	//PRINT PROGRAM
	printf("~~~~~CONTENTS OF ARP RESPONSE~~~~~\n");
        printf("ARP opcode : %d\n", ntohs(ah.ea_hdr.ar_op));
        printf("Sender MAC address : %s\n", ether_ntoa((struct ether_addr *)&ah.arp_sha));
        printf("Sender IP adress : %s\n", inet_ntoa(*(struct in_addr*)&ah.arp_spa));	 
        printf("Target MAC addr : %s\n", ether_ntoa((struct ether_addr *)&ah.arp_tha));	 
        printf("Target IP addr : %s\n", inet_ntoa(*(struct in_addr*)&ah.arp_tpa));
        printf("~~~~~ETHER HEADER CONTENTS~~~~~\n");
        printf("SRC MAC ADDR : %s\n", ether_ntoa((struct ether_addr *)&eh.ether_shost));
        printf("DST MAC ADDR : %s\n", ether_ntoa((struct ether_addr *)&eh.ether_dhost));
        printf("~~~~~END OF PACKET~~~~~\n\n");

	//SEND REPLY
	printf("\nWE SENT IT ON %d\n", sockfd);
	send(sockfd,reply,sizeof(reply),0);      
}

void icmp_response( char * buf, struct interface ** if_list, int idx, int sockfd){

	fflush(stdout);

	//STRUCTS
	struct ether_header eh;
	struct iphdr iph;
	struct icmp_hdr icmp;
	
	//READ IN STRUCTS
	memcpy(&eh,&buf[0],14);
	memcpy(&iph,&buf[14],20);
	memcpy(&icmp,&buf[34],64);

	//PRINT PROGRAM
	printf("\n~~~~~~ECHO REQUEST CONTENTS~~~~~~\n");
        printf("MAC SRC %s\n", ether_ntoa((struct ether_addr*)eh.ether_shost));
        printf("MAC DST %s\n", ether_ntoa((struct ether_addr*)eh.ether_dhost));
        printf("IP SRC %s\n", inet_ntoa(*(struct in_addr*)&iph.saddr));
        printf("IP DST %s\n", inet_ntoa(*(struct in_addr*)&iph.daddr));
        printf("TYPE %d\n", icmp.type);

	//									                       //
	///////////////////////////////////////////BUILD RESPONSE////////////////////////////////////////
	//							  				       //
	
	///////////////////////
	//SET UP ETHER HEADER//
	///////////////////////
	u_int8_t tmp_src_mac[6];			//Tmp source mac.
	memcpy(tmp_src_mac,&eh.ether_shost,6);		//Grab old sender mac addr.
	memcpy(&eh.ether_shost,&eh.ether_dhost,6);	//Make new sender mac addr the old dest.
	memcpy(&eh.ether_dhost,tmp_src_mac,6);		//Make new dest the old sender addr.
	
	////////////////////
	//SET UP IP HEADER//
	////////////////////
	uint32_t tmp_src_ip;				//Tmp srouce ip.
        memcpy(&tmp_src_ip,&iph.saddr,4);		//Grab old sender ip.
	memcpy(&iph.saddr,&iph.daddr,4);		//Make new sender ip the old dest.
	memcpy(&iph.daddr,&tmp_src_ip,4);		//Make new dest ip the old sender ip.

	//////////////////////
	//SET UP ICMP HEADER//
	//////////////////////
	icmp.type = ICMP_ECHOREPLY;			 //Set the type of the ICMP header.

	//RECALC CHECKSUM		
	unsigned short chk_sum_buf[32];			 //Create a buf for the check sum.
	memcpy(chk_sum_buf,&icmp,64);			 //Copy all of ICMP packet into buffer.
	unsigned short new_cksum = cksum(chk_sum_buf,32);//Calc the check sum.
	memcpy(&icmp.check_sum,&new_cksum,2);		 //Copy in the new check sum.TODO check sum is not zeroed out, fix this.

	/////////////////
	//SEND RESPONSE//
	/////////////////

	unsigned char reply[98];			 //The reply.
	memcpy(&reply[0],&eh,14);			 //Copy in the the ether header.
	memcpy(&reply[14],&iph,20);			 //Copy in the ip header.
	memcpy(&reply[34],&icmp,64);			 //Copy in the icmp header.

	//PRINT PROGRAM
	printf("\n~~~~~~ECHO RESPONSE CONTENTS~~~~~~\n");
	printf("MAC SRC %s\n", ether_ntoa((struct ether_addr*)eh.ether_shost));
	printf("MAC DST %s\n", ether_ntoa((struct ether_addr*)eh.ether_dhost));
	printf("IP SRC %s\n", inet_ntoa(*(struct in_addr*)&iph.saddr));
	printf("IP DST %s\n", inet_ntoa(*(struct in_addr*)&iph.daddr));
	printf("TYPE %d\n", icmp.type);
	
	//SEND RESPONE ON THE SAME SOCKET
	send(sockfd,reply,sizeof(reply),0);		 //Send it.
	printf("SENT ON SOCKET %d\n", sockfd);		 //Print program.
}

int main(int argc, char ** argv){

	//INITIALIZE VARIABLES
	int packet_socket;	
	struct sockaddr_ll * if_addr_ll; 
	struct sockaddr_in * if_addr_in; 
	struct interface * if_list[5];
	struct fwd_atr * fwd_table[5];
	struct packet * pkt_list[1000];
	

	fd_set p_sockets;

	//ALLOCATE MEM SET UP FD SET
	int i;
	for(i=0; i<5; i++)
		if_list[i] = (struct interface *) malloc(sizeof(struct interface));
	for(i=0; i<5; i++)
		fwd_table[i] = (struct fwd_atr *) malloc(sizeof(struct fwd_atr));
	for(i=0; i<1000; i++){
		pkt_list[i] = (struct  packet *) malloc(sizeof(struct packet));
		pkt_list[i]->open = 1;//Set packet to open
	}

	FD_ZERO(&p_sockets);

	//GET LIST OF INTERFACES
	struct ifaddrs *ifaddr, *tmp;
	if(getifaddrs(&ifaddr)==-1){
		perror("getifaddr");
		return 1;
	}

	//HAVE LIST, LOOP THROUGH IT
	for(tmp = ifaddr; tmp != NULL; tmp=tmp->ifa_next){
		if(tmp->ifa_addr->sa_family==AF_INET){
			//PRINT PROGRAM
			printf("Grabbing IP for interface %s\n", tmp->ifa_name);
			
			if(!strncmp(&(tmp->ifa_name[3]),"eth",3)){
				//GRAB THE INTERFACE NUMBER
				int index = atoi(&tmp->ifa_name[6]);
			
				//GRAB THE IP ADDRESS
				if_addr_in = (struct sockaddr_in *)tmp->ifa_addr;
				if_list[index]->ip = if_addr_in->sin_addr.s_addr;
			}
		}

		if(tmp->ifa_addr->sa_family==AF_PACKET){
			if(!strncmp(&(tmp->ifa_name[3]),"eth",3)){
				//GRAB THE INTERFACE NUMBER	
				int index  = atoi(&tmp->ifa_name[6]);
			
				//GRAB THE MAC ADDRESS
				if_addr_ll = (struct sockaddr_ll *)tmp->ifa_addr;
				memcpy(if_list[index]->mac,if_addr_ll->sll_addr,ETH_ALEN);
				
				//CREATE A PACKET SOCKET
				packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
				if(packet_socket<0){
					perror("socket");
					return 2;
				}

				//ADD PACKET SOCKET TO FD SET
				FD_SET(packet_socket,&p_sockets);
			
				//ADD PACKET SOCKET TO INTERFACE LIST
				if_list[index]->sockfd = packet_socket;
					
				//BIND ADDRESS OF THE INTERFACE TO THE SOCKET
				if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1){
					perror("bind");
				}
				
			}	
		}
	}
		
	//PRINT INTERFACE LIST
	puts("INTERFACE LIST");
	puts("------------------------");
	for(i=0; i<5; i++){
		printf("INTERFACE : ETH%d\n", i);
		printf("IP        : %s\n", inet_ntoa(*((struct in_addr *)&if_list[i]->ip)));
		printf("MAC       : %s\n", ether_ntoa((struct ether_addr *)&if_list[i]->mac));
		printf("FD        : %d\n", if_list[i]->sockfd);
		puts("------------------------");
	}
	
	//READ IN FORWARDING TABLE
	readFile(argv[1],fwd_table);
	
	//PRINT FWD TABLE
	puts("\nFWD TABLE");
	puts("---------------------");
	for(i=0; i<5; i++){
                printf("IP        : %s\n", inet_ntoa(*(struct in_addr *)&fwd_table[i]->ip));
                printf("HOP       : %s\n", inet_ntoa(*(struct in_addr *)&fwd_table[i]->hop));
                printf("PREFIX    : %d\n", fwd_table[i]->prefix);
                printf("INTERFACE : ETH%d\n,", fwd_table[i]->i_num);
                puts("---------------------");
        }

	//WHERE THE MAGIC HAPPENS
	while(1){

		char buf[1500];
		struct sockaddr_ll recvaddr;
		int recvaddrlen = sizeof(struct sockaddr_ll);
		int s_idx;
		int if_idx;
		fd_set tmp;	
			
		tmp = p_sockets;
		select(FD_SETSIZE,&tmp,NULL,NULL,NULL);
		
		for(s_idx = 0; s_idx<FD_SETSIZE; s_idx++){
			if(FD_ISSET(s_idx,&tmp)){
				for(if_idx = 0; if_idx<5; if_idx++){
					if(s_idx == if_list[if_idx]->sockfd){
					/////////////////////////
					/////PROCESS PACKETS/////
					/////////////////////////
			//RECEIVE PACKET
			
			int n = recvfrom(s_idx,buf,1500,0,(struct sockaddr*)&recvaddr,&recvaddrlen);
			
			printf("\nRECEVED A PACKET ON SOCKET %d\n", s_idx);		

			//IGNORE OUTGOING PACKETS
			if(recvaddr.sll_pkttype==PACKET_OUTGOING)
				continue;

///////////////////
//WE GET A PACKET//
///////////////////

/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~THE PLAN~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~/
 *
 *IF(ARP)
 *	CHECK(ONE OF ROUTER INTERFACE IPs with look up function)
 *		IF(ARP REQ) -> send reply 
 *		IF(ARP REPLY) -> look through stored packets for matching SRC OF ARP AND WHAT THE EXPECTED ARP SRC IS
 *	ELSE
 *		IGNORE
 *IF(IP)
 *	CHECK(ROUTER INTERFACE IPs with a look up function)
 *		IF(ICMP REQUEST)
 *	ELSE
 *		FWD TABLE LOOK UP
 *		SEND OUT ARP REQUEST FOR THE PACKET MAC
 *		STORE PACKET WITH THE EXPECTED IP ADDRESS OF THE SENDER BASED ON WHERE IT IS FOWARDED.
 *~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
			int index;
			if(ntohs(recvaddr.sll_protocol) == ETH_P_ARP){

				puts("\nWE GOT AN ARP\n");
				if((index = if_lookup(if_list,buf,0))!=-1){

					//READ IN ARP HEADER AND GRAB ARP OP CODE
					struct ether_arp tmp;
					memcpy(&tmp,&buf[14],28);
					int op = ntohs(tmp.ea_hdr.ar_op);
					
					//RESPOND TO ARP REQUEST
					if(op == ARPOP_REQUEST){
						puts("\nWE GOT AN ARP REQUEST\n");
						arp_response(buf,if_list,index,s_idx);
					}

					//ARP RESPONSE
					if(op == ARPOP_REPLY){ 
						puts("\n\nWE RECEIVED AN ARP RESPONSE!!!\n\n");
						fwd_packet(buf, pkt_list, s_idx);
					}
				}else{
					puts("\nARP WAS NOT FOR US\n");
				}
			}

			//IF IT IS A IP PACKET
			if(ntohs(recvaddr.sll_protocol) == ETH_P_IP){
					
				//PRINT PROGRAM
				puts("\nWE GOT AN IP PACKET\n");
				
				////////////////////////////
				//VERIFY CHECK SUM AND TTL//
				////////////////////////////		
				if(verify_chksum(buf) == 1){				
				if(do_ttl(buf) > 0){
				if(verify_chksum(buf) == 1){
				
					

				//CHECK IF IT IS FOR ONE OF OUR IP ADDRESSES
				if((index = if_lookup(if_list,buf,1))!=-1){	

					//COPY IP HEADER AND GRAB PROTOCOL
					struct iphdr tmp;
					memcpy(&tmp,&buf[14],20);
					int proto = tmp.protocol;
								
					//CHECK IF IT IS AN ICMP PACKET
					if(proto == 1){
						puts("\nGOT ICMP PACKET\n");
						//COPY ICMP HEADER AND GRAB 
						struct icmp_hdr tmp_icmp;
						memcpy(&tmp_icmp,&buf[34],64);
						int type = tmp_icmp.type;
						
						//RESPOND TO ICMP ECHO REQUEST
						if(type == ICMP_ECHO){
							printf("\nWE GOT AN ECHO REQUEST\n");
							icmp_response(buf,if_list,index,s_idx);
						}
					}
				}//CHECK WHERE THE PACKET CAN BE FORWARDED
				else if((index = fwd_lookup(fwd_table,buf))!= -1){
					puts("\nATTEMPT TO FWD PACKET\n");
				 	//SEND ARP REQ
					arp_request(buf,index,fwd_table,if_list,pkt_list,s_idx);
				}else{
					//SEND ICMP DST UNREACHABLE.
					puts("\nICMP NET UNREACHABLE\n");
					icmp_error_msg(buf,s_idx,3,0,if_list);
					
				}
			}//END SECOND CHECKSUM
			}//END TTL
			else{//SEND ICMP TIME X 
				puts("\nTIME EXCEEDED\n");
				icmp_error_msg(buf,s_idx,11,0,if_list);	
			} 
			}//END FIRST CHECK SUM
			}//END IS A IP PACKET
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			//PRINT PROGRAM
			printf("\nPACKET HAS BEEN DEALT WITH\n");
		
			//CHECK FOR PACKETS THAT HAVE EXPIRED	      
			check_timestamp(pkt_list,if_list);	

		}//END SELCTION
	}//END IF_IDX 		
	}//END FD_ISSET
	}//END S_IDX
	}//END WHILE

	//FREE MEMORY
	for(i=0; i<5; i++){
		free(if_list[i]);
		free(fwd_table[i]);
	}
	
	for(i=0; i<1000; i++){
		free(pkt_list[i]);
	}
}
