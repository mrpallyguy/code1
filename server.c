#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
void error()
{
    exit(0);
}
int array_length( char * array )
{
    int length = 0;
    while( array[length] != NULL )
    {
	length++;
    }
    return length;
}
void parse_port(int argc, char * argv[], char * port_temp)
{
    char port[array_length(argv[1])];
    for( int i = 0; i < array_length(argv[1]); i++ )
    {
	port[i] = argv[1][i];

    }
    for ( int j = 7; j < array_length(port); j++ )
    {
	port_temp[j-7] = port[j];
    }
}
DH * dif_hel_setup()
{
    DH * new_dh = DH_new();
    if ( !new_dh )
    {
	printf("%s \n","Error:Creating new dh");
	error();
    }
    if ( !DH_generate_parameters_ex(new_dh,2,DH_GENERATOR_2,0))
    {
	printf("%s \n","Error:Generating paramters");
	error();
    }
    int dh_code = 0;
    if( !DH_check(new_dh,&dh_code))
    {
	printf("%s \n", "Error:Dh_check failed");
	error();
    }
    if(!DH_generate_key(new_dh))
    {
	printf("%s \n", "Error:Generating key failed");
	error();
    }
    return new_dh;
}
SSL_CTX * dh_setup_ctx()
{
    SSL_CTX* new_ctx;
    if (!(new_ctx = SSL_CTX_new(TLSv1_server_method())))
    {
	printf("%s \n","Error:SSL_CTX_new failed");
	error();
    }
    DH * new_dh = dif_hel_setup();

    SSL_CTX_set_tmp_dh(new_ctx,new_dh);
    
    if( SSL_CTX_set_cipher_list(new_ctx, "ADH-AES256-SHA" ) != 1 )
    {
	printf("%s \n","Error:Cipher list set failed");
	error();
    }
    return new_ctx;

}
int main(int argc, char *argv[])
{
    SSL_library_init();
    SSL_load_error_strings();
    
    SSL * new_ssl;
    SSL_CTX * new_ctx;
    
    new_ctx = dh_setup_ctx();
    
    BIO * acc, * client;
    char port[sizeof(argv[1])] = "";  
    int check = 0;
    long port_num;
    parse_port(argc,argv,port);
    acc = BIO_new_accept("1300");
    port_num = BIO_set_accept_port(acc,port);
    if ( !acc )
    { 
	printf("%s \n", "Error in new bio accept");
	return -1;
    }
    if ( BIO_do_accept(acc) <= 0)
    {
	printf("%s \n", "Error in do accept" );
	return -1;
    }
    int get = 0;
    while ( 1 )
    {
	if( BIO_do_accept(acc) <= 0 )
	{
	    printf("%s \n", "Error in accepting connections");
	    return -1;
	}
	client = BIO_pop(acc);
	if ( !(new_ssl = SSL_new(new_ctx)))
	{
	    printf("%s \n", "Error in creating new SSL");
	    return -1;
	}
	SSL_set_bio(new_ssl,client,client);
	if( SSL_accept(new_ssl) <= 0 )
	{
	    get = SSL_get_error(new_ssl,get);
	    printf("%s \n", "Error in accepting SSL connection");
	    printf("%d \n", get);
	    printf("%s \n",ERR_error_string(get,NULL)); 
	    return -1;
	}
	int buf[256] = { 0 };
	int count = 0;
	if ( SSL_read(new_ssl,buf,sizeof(buf)) > 0)
	{
	    /*get = SSL_get_error(new_ssl,get);
	    printf("%d \n", get);
	    printf("%s \n",ERR_error_string(get,NULL)); 
*/
	    while( (char)buf[count] != EOF )
	    {
		printf("%c" , (char)buf[count]);
		count++;
	    }
	}
	SSL_shutdown(new_ssl);
	SSL_free(new_ssl);
    }
    SSL_CTX_free(new_ctx);
    BIO_free(acc);
    return 0;
}


