#pragma once
/**
*header file of CreAndSenPac.c
*Author Alexey Titov
*Version 1.0
**/
//libraries
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include "Attacker.h"

// IPv4 header length
#define IP4_HDRLEN 20
// TCP header length
#define TCP_HDRLEN 20

#define	IPVERSION	4               /* IP version number */
#define	IP_MAXPACKET	65535		/* maximum packet size */
#define	MAXTTL		128		        /* maximum time to live (seconds) */

#define MAX_IP 255
#define IP_LENGTH 15

//this function compute checksum (RFC 1071)
//source: https://stackoverflow.com/questions/30855053/rfc-1071-calculating-ip-header-checksum-confusion-in-c
unsigned short calculate_checksum(unsigned short * iphead, const int len);

//this function creates the new packet, and sends it to victim's IP
void CreateAndSend(const char * dstAddr, const int dstPort, const int isSyn, const int number);

//this function generates a random correct IP Address
unsigned int RandomIP();

//this function returns a number integer between 0-max
int getRandom(const int max);

//this function allocates memory on the heap for the valid ip address (char *)
void mallocString(const int a, const int b,const int c,const int d, char ** str);

//this function returns length of int a
int Lenght(int a);