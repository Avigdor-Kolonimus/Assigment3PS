#pragma once
/**
*header file of Attacker.c
*Author Alexey Titov
*Version 1.0
**/
//libraries
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "CreAndSenPac.h"

#define LOCAL_HOST "127.0.0.1"		//localhost
#define HTTP 80						//assignment request
#define NUM 1                       //number of attacks
#define IP_LENGTH 15				//xxx.xxx.xxx.xxx
#define MAX_PORT_NUM 65535			//ports are between 0—65535

//this procedure print instraction how user run this program
void printInstruction();

//this function checks if the entered address is correct 0-no, other-yes
int checkIP(const char * ip);

//this function check port and return number of port if he is coorrect otherwise -1
int checkPort(const char * port);

//this function attack dstAddr via dstPort
void sendAttack(const char * dstAddr,const int dstPort,const int isSyn, const int number);