//Manojit Chakraborty
//Roll 2018201032


#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include<iostream>
#include<string>
#include<math.h>
#include<vector>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <limits>
#include <math.h>
#include <random>
#include<thread>
using namespace std;

#define SERV_PORT 19000
#define MAX_LEN 1024
#define CAESAR_MOD 66	
#define LISTEN_Q 5
#define MAX_SIZE 80


typedef struct {
int opcode; 
int s_addr; 
int d_addr; 
} Hdr;


typedef struct{
  string userid;
  long long salt;
  long long hash;
  long long prime;
}user;


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
  char opcode[MAX_SIZE]; 
  char s_addr[MAX_SIZE]; 
  char d_addr[MAX_SIZE]; 
} EncryptHdr;

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

vector<user> users;

typedef struct GlobalVar {
	int prime;
	int small_g;
} GlobalVar;

char dict[] = {' ','A','B','C','D','E','F','G','H','I','J','K','L','M','N',
								'O','P','Q','R','S','T','U','V','W','X','Y','Z',',','.',
								'?','0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i',
                                'j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','!'};

int compute_exp(int a, int b, int p) {
	long long x = 1, y = a;
	while (b > 0) {
		if (b % 2 == 1)
			x = (x * y) % p;
		y = (y * y) % p;
		b /= 2;
	}
	return (int)(x % p);
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
	for (int i = 0; i < CAESAR_MOD; i++) {
		if (dict[i] == c) 
			return dict[(CAESAR_MOD + i - key) % CAESAR_MOD];
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
	for (int j = 0; j <66; j++) {
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
  string op_code=to_string(send_msg.hdr.opcode);
  op_code=caesar_encrypt2(op_code,caesar_key);
  string status(send_msg.status);
  status=caesar_encrypt2(status,caesar_key);
  strcpy(encr_msg.hdr.opcode,op_code.c_str());
  strcpy(encr_msg.status,status.c_str());
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

Msg decrypt_msg(EncryptMsg encr_msg,long long caesar_key){
  Msg dec_msg;
  string opcode(encr_msg.hdr.opcode);
  string userid(encr_msg.ID);
  string password(encr_msg.password);
  string q(encr_msg.q);
  int op_code=atoi(caesar_decrypt2(opcode,caesar_key).c_str());
  if(op_code==10){
      dec_msg.hdr.opcode=op_code;
      strcpy(dec_msg.ID,caesar_decrypt2(userid,caesar_key).c_str());
      strcpy(dec_msg.password,caesar_decrypt2(password,caesar_key).c_str());
      dec_msg.q=atoll(caesar_decrypt2(q,caesar_key).c_str());
  }
  else if(op_code==30){
      dec_msg.hdr.opcode=op_code;
      strcpy(dec_msg.ID,caesar_decrypt2(userid,caesar_key).c_str());
      strcpy(dec_msg.password,caesar_decrypt2(password,caesar_key).c_str());
  }
  return dec_msg;
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


void server_loop(int cfd,long long caesar_key){
  int number_bytes;
  while(true){
    Msg dec_recv_msg,send_msg;
    EncryptMsg enc_send_msg,enc_recv_msg;
    number_bytes=recv(cfd,&enc_recv_msg,sizeof(enc_recv_msg),0);
    if (number_bytes<=0){
       fprintf(stderr, "Server error: unable to receive\n");
       //exit(EXIT_FAILURE);
       break;
     }
     
      dec_recv_msg=decrypt_msg(enc_recv_msg,caesar_key);
      int opcode=dec_recv_msg.hdr.opcode;
      //cout<<opcode<<endl;
      if(opcode==10){
        cout<<"=====LOGIN CREATE REQUEST====="<<endl;
        cout<<"Decrypted data : "<<endl;
        cout<<"opcode :"<<dec_recv_msg.hdr.opcode<<endl;
        string userid(dec_recv_msg.ID);
        string password(dec_recv_msg.password);
        long long q=dec_recv_msg.q;
        cout<<"User Id :"<<userid<<endl;
        cout<<"Password :"<<password<<endl;
        cout<<"Prime :"<<q<<endl;
        bool found=false;
        for(int i=0;i<users.size();i++){
          if(userid==users[i].userid){
            found=true;
          }
        }
        if(found){
          send_msg.hdr.opcode=20;
          string rep="NO";
          strcpy(send_msg.status,rep.c_str());
          EncryptMsg enc_send_msg=encrypt_msg(send_msg,caesar_key);
          int number_bytes=send(cfd,&enc_send_msg,sizeof(enc_send_msg),0);
          if(number_bytes<=0){
            cout<<"Failed to send data to client"<<endl;
          }
        }
        else{
          long long sum=0;
          long long salt=rand();
          for(int i=0;password[i];i++){
            sum+=(int)password[i];
          }
          long long pass_hash=compute_exp((sum+q+salt),3,q);
          user temp_user;
          temp_user.userid=userid;
          temp_user.salt=salt;
          temp_user.hash=pass_hash;
          temp_user.prime=q;
          users.push_back(temp_user);
          send_msg.hdr.opcode=20;
          string rep="YES";
          strcpy(send_msg.status,rep.c_str());
          EncryptMsg enc_send_msg=encrypt_msg(send_msg,caesar_key);
          int number_bytes=send(cfd,&enc_send_msg,sizeof(enc_send_msg),0);
          if(number_bytes<=0){
            cout<<"Failed to send data to client"<<endl;
          }
        }
      }
      else if(opcode==30){
        cout<<"=====AUTH REQUEST====="<<endl;
        string userid(dec_recv_msg.ID);
        string password(dec_recv_msg.password);
        long long q=dec_recv_msg.q;
        cout<<"Decrypted data :"<<endl;
        cout<<"User Id:"<<userid<<endl;
        cout<<"Password:"<<password<<endl;
        bool found=false;
        user temp_user;
        for(int i=0;i<users.size();i++){
          if(userid==users[i].userid){
            found=true;
            temp_user=users[i];
            break;
          }
        }
        if(!found){
          cout<<"User does not exist"<<endl;
          send_msg.hdr.opcode=40;
          string rep="NO";
          strcpy(send_msg.status,rep.c_str());
          EncryptMsg enc_send_msg=encrypt_msg(send_msg,caesar_key);
          send(cfd,&enc_send_msg,sizeof(enc_send_msg),0);
        }
        else{
          long long sum=0;
          long long salt=temp_user.salt;
          long long prime=temp_user.prime;
          for(int i=0;password[i];i++){
            sum+=(int)password[i];
          }
          long long pass_hash=compute_exp((sum+prime+salt),3,prime);
          if(pass_hash==temp_user.hash){
            cout<<"=====Password matched====="<<endl;
            Msg send_msg;
            send_msg.hdr.opcode=40;
            string rep="YES";
            strcpy(send_msg.status,rep.c_str());
            EncryptMsg enc_send_msg=encrypt_msg(send_msg,caesar_key);
            send(cfd,&enc_send_msg,sizeof(enc_send_msg),0);
          int opcode;
          recv(cfd,&opcode,sizeof(opcode),0);
          if(opcode==50){
          char filename[MAX_SIZE];
					//cout<<"Enter the filename"<<endl;
					//cin>>filename;
					recv(cfd,&filename,sizeof(filename),0);
          //cout<<filename<<endl;
          for (int i = 0; i < strlen(filename); i++) {
                filename[i] = caesar_decrypt(filename[i], caesar_key);
              }
            //cout<<filename<<endl;
            FILE *p_file = NULL;
            //char ffile[MAX_SIZE];
            //strcpy(ffile,password5.c_str());
            int opcode2=60;
            send(cfd,&opcode2,sizeof(opcode2),0);
            if((p_file = fopen(filename,"rb"))==NULL){
              string auth="NO";
              send(cfd,&auth,sizeof(auth),0);
              continue;
            };
            string auth="YES";
            send(cfd,&auth,sizeof(auth),0);
            fseek(p_file,0,SEEK_END);
            int size = ftell(p_file);
            //cout<<"size"<<size<<endl;
            fclose(p_file);
            send(cfd,&size,sizeof(size),0);
            FILE *ip1;
            if ((ip1 = fopen(filename, "r")) == NULL) {
              perror("Error ");
              exit(-1);
            }
            printf("=====Sending file to server in encrypted format=====\n");
            int n;
            char message[MAX_LEN];
            int sum=0;
            int msize=1024;
            //if(size<msize){
              //  msize=size;
            //}
            while ((n = fread(message, sizeof(char), MAX_LEN, ip1)) > 0) {
              //cout<<message<<endl;
              for (int i = 0; i < n; i++) {
                message[i] = caesar_encrypt(message[i], caesar_key);
              }
              
              int a=send(cfd,&message,sizeof(message),0);
              char auth2[MAX_SIZE]="SERVICEDONE SUCCESSFUL";
              send(cfd,&auth2,sizeof(auth2),0);
              //cout<<a<<endl;
              sum+=sizeof(message);
              //cout<<"now size"<<sum<<endl;
              msize=size-sum;
              if(size<=sum){
                fclose(ip1);
                cout<<"File sent to the client :)"<<endl;
                break;
              }
              //send_message(cfd, message, n);
              
            } 
            fclose(ip1);
            //cout<<"File sent to the client";
          }
                
          }
          else{
            cout<<"=====Password not matched====="<<endl;
            Msg send_msg;
            send_msg.hdr.opcode=40;
            string rep="NO";
            strcpy(send_msg.status,rep.c_str());
            EncryptMsg enc_send_msg=encrypt_msg(send_msg,caesar_key);
            send(cfd,&enc_send_msg,sizeof(enc_send_msg),0);
          }
        }   
  }

}

}

int main(int argc, char *argv[]) {
	cout<<"=====SERVER SIDE=====\n";
	cout<<"Server started! Waiting for connection ..\n\n";
	GlobalVar g;
	int server_sockfd, client_sockfd;
	if ((server_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("Error ");
		exit(-1);
	}
	struct sockaddr_in serv_addr;
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(SERV_PORT);
	if (bind(server_sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
		perror("Error ");
		exit(-1);
	}
	listen(server_sockfd, LISTEN_Q);
	while (1) {
		if ((client_sockfd = accept(server_sockfd, NULL, NULL)) < 0) {
			perror("Error ");
			exit(-1);
		}
		cout<<"Client connected :) \n\n";
		char buffer[MAX_LEN];
		memset(buffer, 0, sizeof(buffer));
		int recv_size = sizeof(int) * 3 + sizeof(char) * 3;
		int n = recv_message(client_sockfd, buffer, recv_size);
		int public_key_client = atoi(buffer);
		int i = 0;
		while (buffer[i] != '\n') 
			i++;
		g.prime = atoi(buffer + ++i);
		while (buffer[i] != '\n')
			i++;
		g.small_g = atoi(buffer + ++i);
    cout<<"Global prime : "<<g.prime<<endl;
		cout<<"Global primitive root : "<<g.small_g<<endl;
		cout<<"Client public key : "<<public_key_client<<endl<<endl;
		int private_key = rand()%(g.prime - 1) + 1;
		int public_key = compute_exp(g.small_g, private_key, g.prime);
		cout<<"Server private key : "<<private_key<<endl;
		cout<<"Server public key : "<<public_key<<endl<<endl;
		n = sprintf(buffer, "%d\n", public_key);
		send_message(client_sockfd, buffer, n); 
		int shared_key = compute_exp(public_key_client, private_key, g.prime);
		long long int caesar_key = shared_key %66;
		cout<<"Shared key : "<<shared_key<<endl;
		cout<<"Caesar key : "<<caesar_key<<endl<<endl;
        //std::thread t(server_loop,client_sockfd,caesar_key);
        //t.join();
        //t.detach();
    server_loop(client_sockfd,caesar_key);
		close(client_sockfd);
	}
	return 0;
}

