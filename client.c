#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <getopt.h>
int error()
{
    exit(0);
}
int array_l(char * array)
{
    int length = 0;
    while( array[length] != NULL )
    {
	length++;
    }
    return length;
}
void parse_sa(int argc, char * argv[],char * sa_temp)
{
    char sa[array_l(argv[1])];
    for(int i = 0; i < array_l(argv[1]); i++ )
    {
	sa[i] = argv[1][i];
    }
    for(int j = 16; j < array_l(argv[1]); j++ )
    {
	sa_temp[j-16] = argv[1][j];
    }
}
void parse_port(int argc, char * argv[], char * pp_temp )
{
   
    char sa[array_l(argv[2])];
    for(int i = 0; i < array_l(argv[2]); i++ )
    {
	sa[i] = argv[2][i];
    }
    for(int j = 7; j < array_l(argv[2]); j++ )
    {
	pp_temp[j-7] = argv[2][j];
    }
}
void parse_sr(int argc, char * argv[], char * sr_temp )
{
    char sa[array_l(argv[3])];
    for(int i = 0; i < array_l(argv[3]); i++ )
    {
	sa[i] = argv[3][i];
    }
    for( int j = 2; j < array_l(argv[3]); j++ )
    {
	sr_temp[j-2] = argv[3][j];
    }
}
SSL_CTX * ssl_ctx_setup()
{
    SSL_CTX * ctx;
    ctx = SSL_CTX_new(TLSv1_client_method());
    if( !ctx )
    {
	printf("%s \n", "Error:Client method error");
    }
    if ( SSL_CTX_set_cipher_list(ctx, "ADH-AES256-SHA") != 1)
    {
	printf("%s \n", "Error:Set cipher list");
    }
    return ctx;
}
void read_file(FILE * fp,int c, int * storage,char * argv[])
{
    int length = 0;
    fp = fopen(argv[4], "r" );
    if ( !fp )
    {
	printf("%s \n","File does not exist");
    }
    
    while ( ( c = fgetc(fp)) != EOF )
    {
	storage[length] = c;
	length++;
    }
    storage[length] = EOF;
    fclose(fp);
}
void send_file(FILE * fp, int c, int * storage,SSL * ssl,char * argv[])
{
    read_file(fp,c,storage,argv);
    if( SSL_write(ssl,storage,256) < 0 )
    {
	printf("%s \n", "Error in writing to server!");
	error();
    }
}
void recieve_file(FILE * fp, int c, int * storage);
int main(int argc, char * argv[])
{
    SSL_library_init();
    SSL_load_error_strings();
    SSL * ssl;
    SSL_CTX * ctx;
    long port_num, sa_num;
    BIO * new_bio;
    char sa[50],port[50],sr[50];
    FILE * buffer;
    int a;
    int file_storage[256] = {0};    
    int count = 0;
    ctx = ssl_ctx_setup();
    
    parse_sa(argc, argv, sa);
    parse_port(argc, argv, port);
    parse_sr(argc,argv,sr);

    new_bio = BIO_new_connect("localhost:13011");
    port_num = BIO_set_conn_port(new_bio,port);
    sa_num = BIO_set_conn_hostname(new_bio,sa); 

    if(!new_bio)
    {
	printf("%s \n", "Error in creating connection");
	return -1;
    }
    if ( BIO_do_connect(new_bio) <= 0 )
    {
	printf("%s \n","Error:Connection not established");
	return -1;
    }
    if( !(ssl = SSL_new(ctx)) )
    {
	printf("%s \n", "Error:Creating new SSL connection failed");
	return -1;
    }
    SSL_set_bio(ssl,new_bio,new_bio);
    if( SSL_connect(ssl) <= 0 )
    {
	printf("%s \n", "Error:SSL connection failed");
	return -1;
    
    }
    if ( sr[0] == 's' )
    {
	send_file(buffer,a,file_storage,ssl,argv);	
    }
    else if ( sr[0] == 'r' ) 
    {
	read_file(buffer,a,file_storage,argv);
	while( file_storage[count] != EOF )
	{
	    printf("%c",(char)file_storage[count]);
	    count++;
	}
	printf("%s \n","");
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

