//Manojit Chakraborty
//Roll 2018201032

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <math.h>
#include <ctype.h>
#include<string>
#include<iostream>
#include<fstream>
using namespace std;

#define MAX_SIZE 80
#define SERV_PORT 19000
#define MAX_LEN 1024
#define MAXSIZE 1000000
#define CAESAR_MOD 66
#define M_ITERATION 15

typedef struct {
int opcode; 
int s_addr; 
int d_addr; 
} Hdr;

typedef struct {
  char opcode[MAX_SIZE]; 
  char s_addr[MAX_SIZE]; 
  char d_addr[MAX_SIZE]; 
} EncryptHdr;

typedef struct {
  Hdr hdr;
  char buf[MAX_LEN];
  char ID[MAX_SIZE];
  long long q;
  char password[MAX_SIZE];
  char status[MAX_SIZE];
  char file[MAX_SIZE]; 
  int dummy;
} Msg;

typedef struct {
  EncryptHdr hdr;
  char buf[MAX_LEN];
  char ID[MAX_SIZE];
  char q[MAX_SIZE];
  char password[MAX_SIZE];
  char status[MAX_SIZE];
  char file[MAX_SIZE]; 
  char dummy[MAX_SIZE];
} EncryptMsg;

typedef struct GlobalVar {
	int prime;
	int small_g;
} GlobalVar;


int compute_exp(int a,int b,int p){
	long long x=1,y=a;
	while(b>0){
		if(b%2==1)
			x=(x*y)%p;
		y=(y*y)%p;
		b/=2;
	}
	return (int)(x%p);
}


int MillerRabin(int value, int iteration){
	if(value<2)
		return 0;
	int q=value-1,k=0;
	while(!(q%2)){
		q/=2;
		k++;
	}
	for(int i=0;i<iteration;i++){
		int a=rand()%(value-1)+1;
		int current=q;
		int flag=1;
		int mod_result=compute_exp(a,current,value);
		for(int i=1;i<=k;i++){
			if(mod_result==1||mod_result==value-1){
				flag=0;
				break;
			}
			mod_result=(int)((long long)mod_result * mod_result%value);
		}
		if(flag)
			return 0;
	}
	return 1;
}


int CreatePrime(){
	srand(time(NULL));
	while(1){
		int current_value=rand()%INT_MAX;
		if(!(current_value%2))
			current_value++;
		if(MillerRabin(current_value,M_ITERATION)==1)
			return current_value;
	}
}


int CreateRoot(int p){
	int sieve[MAXSIZE];
	memset(sieve,0,sizeof(sieve));
	sieve[0]=sieve[1]=1;
	for(int i=4;i<MAXSIZE;i+=2)
		sieve[i]=1;
	for(int i=3;i<MAXSIZE;i+=2) {
		if(!sieve[i]){
			for(int j=2*i;j<MAXSIZE;j+=i)
				sieve[j]=1;
		}
	}
	while(1){
		int a=rand()%(p-2)+2;
		int phi=p-1,flag=1,root=sqrt(phi);
		for(int i=2;i<=root;i++){
			if(!sieve[i] && !(phi%i)){
				int mod_result = compute_exp(a,phi/i,p);
				if (mod_result==1){
					flag=0;
					break;
				}
				if(MillerRabin(phi/i,M_ITERATION) && !(phi%(phi/i))){
					int mod_result = compute_exp(a,phi/(phi/i),p);
					if(mod_result==1){
						flag=0;
						break;
					}
				}
			}
		}
		if(flag) 
			return a;
	}
}


char caesar_encrypt(char c, int key) {
	char dict[] = {' ','A','B','C','D','E','F','G','H','I','J','K','L','M','N',
								'O','P','Q','R','S','T','U','V','W','X','Y','Z',',','.',
								'?','0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i',
                                'j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','!'};
	for (int i = 0; i <66; i++) {
		if (dict[i] == c) 
			return dict[(i + key) %66];
	}
	return c;
}

char caesar_decrypt(char c, int key) {
	char dict[] = {' ','A','B','C','D','E','F','G','H','I','J','K','L','M','N',
								'O','P','Q','R','S','T','U','V','W','X','Y','Z',',','.',
								'?','0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i',
                                'j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','!'};
	for (int i = 0; i <66; i++) {
		if (dict[i] == c) 
			return dict[(i - key+66) %66];
	}
	return c;
}

string caesar_encrypt2(string c, int key) {
	int n=c.size();
	string s;
	s.resize(n,' ');
	char dict[] = {' ','A','B','C','D','E','F','G','H','I','J','K','L','M','N',
								'O','P','Q','R','S','T','U','V','W','X','Y','Z',',','.',
								'?','0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i',
                                'j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','!'};
	for(int i=0;i<n;i++)
	{
	for (int j = 0; j < 66; j++) {
		if (dict[j] == c[i]){ 
			s[i]=dict[(j+key)%66];
			break;
		}
	}
	}
	return s;
}

EncryptMsg encrypt_msg(Msg send_msg,int caesar_key)
{
	EncryptMsg encr_msg;
  if(send_msg.hdr.opcode==10){
    string op_code=to_string(send_msg.hdr.opcode);
    op_code=caesar_encrypt2(op_code,caesar_key);
    string userid(send_msg.ID);
    userid=caesar_encrypt2(userid,caesar_key);
    string password(send_msg.password);
    password=caesar_encrypt2(password,caesar_key);
    string prime=to_string(send_msg.q);
    prime=caesar_encrypt2(prime,caesar_key);
    strcpy(encr_msg.hdr.opcode,op_code.c_str());
    strcpy(encr_msg.ID,userid.c_str());
    strcpy(encr_msg.password,password.c_str());
    strcpy(encr_msg.q,prime.c_str());
    return encr_msg;
  }
  else if(send_msg.hdr.opcode==30){
    string op_code=to_string(send_msg.hdr.opcode);
    op_code=caesar_encrypt2(op_code,caesar_key);
    string userid(send_msg.ID);
    userid=caesar_encrypt2(userid,caesar_key);
    string password(send_msg.password);
    password=caesar_encrypt2(password,caesar_key);
    strcpy(encr_msg.hdr.opcode,op_code.c_str());
    strcpy(encr_msg.ID,userid.c_str());
    strcpy(encr_msg.password,password.c_str());
    return encr_msg;
  }
	return encr_msg;
}

string caesar_decrypt2(string ip1,int caesar_key){
  int n=ip1.size();
  string s;
  s.resize(n,' ');
  char dict[] = {' ','A','B','C','D','E','F','G','H','I','J','K','L','M','N',
								'O','P','Q','R','S','T','U','V','W','X','Y','Z',',','.',
								'?','0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i',
                                'j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','!'};
	for(int i=0;i<n;i++)
	{
		for(int j=0;j<66;j++)
		{
			if(ip1[i]==dict[j])
			{	
				s[i]=dict[(j - caesar_key + 66) % 66];
				break;
			}	
		}
	}
	return s;
}

Msg decrypt_msg(EncryptMsg recv_msg,int caesar_key){
  
    Msg msg;
    string temp_user(recv_msg.hdr.opcode);
    string status(recv_msg.status);
    msg.hdr.opcode=atoi(caesar_decrypt2(temp_user,caesar_key).c_str());
    strcpy(msg.status,caesar_decrypt2(status,caesar_key).c_str());
    return msg;
}



void send_message(int sockfd, char message[MAX_LEN], int len) {
	int n_sent = 0;
	while (n_sent < len) {
		int temp_user;
		if ((temp_user = send(sockfd, message + n_sent, len - n_sent, 0)) <= 0) {
			perror("Error ");
			exit(-1);
		}
		n_sent += temp_user;
	}
}

int recv_message(int sockfd, char buffer[MAX_LEN], int recv_size) {
	int n_recv = 0;
	while (n_recv < recv_size) {
		int temp_user;
		if ((temp_user = recv(sockfd, buffer + n_recv, MAX_LEN - n_recv, 0)) <= 0) {
			if (temp_user == 0)
				break;
			perror("Error ");
			exit(-1);
		}
		n_recv += temp_user;
	}
	return n_recv;
}


void client_loop(int cfd,long long caesar_key){
   char buffer[MAX_LEN];
   int ch,status,number_bytes;
   while(true){
     cout<<"What you want to do:"<<endl;
     cout<<"1. Login Create"<<endl;
     cout<<"2. Service Request"<<endl;
		 cout<<"3. Exit"<<endl;
     cin>>ch;
	   if(ch==3){
			 exit(0);
		 }
     else if(ch== 1){
			 cout<<"=====LOGIN REQUEST====="<<endl;
        Msg send_msg,recv_msg;
        string ID,password;
        long long q;
        send_msg.hdr.opcode=10;
        send_msg.hdr.s_addr=1;
        send_msg.hdr.d_addr=2;
        cout<<"Enter user ID"<<endl;
        cin>>ID;
        cout<<"Enter user password"<<endl;
        cin>>password;
        strcpy(send_msg.ID,ID.c_str());  
        strcpy(send_msg.password,password.c_str());  
        q=CreatePrime();
        send_msg.q=q;
        EncryptMsg encr_msg=encrypt_msg(send_msg,caesar_key);
        cout<<"encryped userid is:"<<encr_msg.ID<<endl;
        status=send(cfd, &encr_msg,sizeof(EncryptMsg),0);
        //cout<<status;
        if (status==0) {
            fprintf(stderr,"Client error: unable to send\n");
            return;
        }
        }
    else if(ch==2){
      cout<<"=====AUTH REQUEST====="<<endl;
      Msg send_msg,recv_msg;
      string ID,password;
      send_msg.hdr.opcode=30;
      send_msg.hdr.s_addr=1;
      send_msg.hdr.d_addr=2;
      cout<<"Enter user ID"<<endl;
      cin>>ID;
      cout<<"Enter user password"<<endl;
      cin>>password;
      strcpy(send_msg.ID,ID.c_str());  
      strcpy(send_msg.password,password.c_str());  
      EncryptMsg encr_msg=encrypt_msg(send_msg,caesar_key);
      status=send(cfd, &encr_msg,sizeof(encr_msg),0);
      if (status <= 0) {
          fprintf(stderr, "Client error: unable to send\n");
          return;
      }
    }
    else{
      cout<<"wrong choice:"<<endl;
      continue;
    }
    EncryptMsg recv_msg;
    number_bytes=recv(cfd, &recv_msg, sizeof(recv_msg), 0);
    if (number_bytes<=0){
        fprintf(stderr, "Client error: unable to receive\n");
        break;
    }
    Msg dec_recv_msg=decrypt_msg(recv_msg,caesar_key);
    if(dec_recv_msg.hdr.opcode==20){
      cout<<"=====LOGIN REPLY====="<<endl;
      string test(dec_recv_msg.status);
      if(test=="NO"){
        cout<<"LOGIN FAILED"<<endl;
      }
      else if(test=="YES"){
        cout<<"LOGIN SUCCESSFUL"<<endl;
      }
      else{
        cout<<"INVALID RESPONSE"<<endl;
      }
    }  
    else if(dec_recv_msg.hdr.opcode==40){
        cout<<"=====AUTH REPLY====="<<endl;
        string test(dec_recv_msg.status);
        if(test=="NO"){
          cout<<"AUTH FAILED"<<endl;
        }
        else if(test=="YES"){
          string file_name;
          cout<<"AUTH SUCCESSFUL"<<endl;
					cout<<"\n=====SERVICE REQUEST====="<<endl;
					int opcode=50;
					send(cfd,&opcode,sizeof(opcode),0);
					char filename[MAX_SIZE],filename1[MAX_SIZE];
					cout<<"Enter the filename :"<<endl;
					cin>>filename;
					for (int i = 0; i < strlen(filename); i++) {
							filename1[i] = caesar_encrypt(filename[i], caesar_key);
							//printf("%c", buffer[i]);
							
						}
					//cout<<filename<<endl;
					send(cfd,&filename1,sizeof(filename1),0);
					//FILE* output = fopen("output.txt","w");
					int opcode2;
          recv(cfd,&opcode2,sizeof(opcode2),0);
					string auth;
					if(opcode2==60){
          recv(cfd,&auth,sizeof(auth),0);
					cout<<"=====SERVICE REPLY====="<<endl;
					if(auth=="NO"){
						cout<<"SERVICE UNSUCCESSFUL"<<endl;
						continue;
					}
					int n;
					ofstream myfile;
					myfile.open(filename);
					//myfile << "Writing this to a file.\n";
					int size;
					recv(cfd,&size,sizeof(size),0);
					int sum=0;
                    int msize=sizeof(buffer);
					while (recv(cfd,&buffer,sizeof(buffer),0) > 0) {
						int k=strlen(buffer);
						for (int i = 0; i < k; i++) {
							buffer[i] = caesar_decrypt(buffer[i], caesar_key);
							//printf("%c", buffer[i]);
							
						}
						char auth2[MAX_SIZE];
							memset(auth2,'\0',sizeof(auth2));
              recv(cfd,&auth2,sizeof(auth2),0);
							cout<<auth2<<endl;
						myfile<<buffer;
						sum+=sizeof(buffer);
                        msize=size-sum;
						if(size<=sum)
							break;
						//fwrite(buffer, sizeof(char), k, output);
						//cout<<"aa"<<endl;
						//break;
					}
					//fclose(output);
					//cout<<"bbb";
					myfile.close();
					printf("\n\nFinished receiving data from server!\n\n");
						
					} 
				}
    }     
  }
   

}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		cout<<"Please enter [IP_ADDRESS]\n";
		exit(-1);
	}
	cout<<"=====CLIENT SIDE=====\n";
	GlobalVar g;	
	g.prime = CreatePrime();
	cout<<"Global prime - "<<g.prime<<endl;
	g.small_g = CreateRoot(g.prime);
	cout<<"Global primitive root - "<<g.small_g<<endl<<endl;
	int private_key = rand() % (g.prime - 1) + 1;
	int public_key = compute_exp(g.small_g, private_key, g.prime);
	cout<<"Client private key : "<<private_key<<endl;
	cout<<"Client public key : "<<public_key<<endl<<endl;
	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Error ");
		exit(-1);
	}
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(SERV_PORT);
	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("Error ");
		exit(-1);
	}
	char message[MAX_LEN];
	memset(message, 0, sizeof(message));	 
	int n = sprintf(message, "%d\n%d\n%d\n", public_key, g.prime, g.small_g);
	send_message(sockfd, message, n);
	n = recv_message(sockfd, message, sizeof(int) + sizeof(char));
	int public_key_server = atoi(message);
	cout<<"Server public key : "<<public_key_server<<endl<<endl;
	int shared_key = compute_exp(public_key_server, private_key, g.prime);
	long long int caesar_key = shared_key % 66;
	cout<<"Shared key : "<<shared_key<<endl;
	cout<<"Caesar key : "<<caesar_key<<endl<<endl;
  client_loop(sockfd,caesar_key);
	close(sockfd);
	return 0;
}



