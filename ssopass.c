#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include "ttymodes.h"

#define OPTSTR "+d:einv"

char *host, *user, *priv_user, *priv_type, *password;

int main(int argc, char *argv[]) {

	ssh_session my_ssh_session;
	int c, rc, passfd;
	struct termios orig_termios;
	char pbuff[20];

        while ((c = getopt(argc, argv, "+d:h:p:s:t:u:")) != EOF) {
                switch (c) {
		case 'd':               /* file descriptor for passing password */
                        passfd = atoi(optarg);
			//read( passfd, pbuff, sizeof(pbuff) );
			int n=read( passfd, pbuff, sizeof(pbuff) );
			if (n<1){
				fprintf(stderr,"Error: No value found on fd %d\n",passfd);
				exit(1);
			}	
			pbuff[n-1]='\0';  /* replace the newline */
			password=pbuff;
                        break;

                case 'h':               /* host */
                        host = optarg;
                        break;

                case 'p':               /* password */
                        password = optarg;
                        break;

		case 's':               /* privileged user */
                        priv_user = optarg;
                        break;

		case 't':               /* sudo or pbrun */
                        priv_type = optarg;
                        break;

		case 'u':               /* non-privileged user */
                        user = optarg;
                        break;

                case '?':
			exit(1);
                }
        }

        if (optind > argc){
                fprintf(stderr, "usage: ssopass -h host -u user [-p password] -s privileged_user [ -t sudo | pbrun ]\n");
		exit(1);
	}

	
	if(host==NULL){
		fprintf(stderr, "Error: No host specified\n");
		exit(1);
	}

	if(user==NULL){
                fprintf(stderr, "Error: No user specified\n");
                exit(1);
        }

	if(priv_type==NULL && priv_user!=NULL){
		fprintf(stderr, "Error: Didn't specify the sudo or pbrun\n");
                exit(1);
        }

	if(priv_user==NULL && priv_type!=NULL){
                fprintf(stderr, "Error: Didn't specify the privileged user\n");
                exit(1);
        }

	if(password==NULL){
                password = getpass("Password: ");
        }

	tcgetattr(STDIN_FILENO, &orig_termios);

	// Open session and set options
	my_ssh_session = ssh_new();
	if (my_ssh_session == NULL)
		exit(-1);

	ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host);
	ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, user);

	// Connect to server
	rc = ssh_connect(my_ssh_session);
	if (rc != SSH_OK) {
		fprintf(stderr, "Error connecting to localhost: %s\n",
		ssh_get_error(my_ssh_session));
		ssh_free(my_ssh_session);
		exit(-1);
	}

	// Verify the server's identity
	// For the source code of verify_knowhost(), check previous example
	/*
	if (verify_knownhost(my_ssh_session) < 0) {
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}
	*/

	// Authenticate ourselves
	rc = ssh_userauth_password(my_ssh_session, NULL, password);
	if (rc != SSH_AUTH_SUCCESS) {
		fprintf(stderr, "Error authenticating with password: %s\n",
		ssh_get_error(my_ssh_session));
		ssh_disconnect(my_ssh_session);
		ssh_free(my_ssh_session);
		exit(-1);
	}

	tcgetattr(STDIN_FILENO, &orig_termios);
	tty_raw(STDIN_FILENO);
        atexit(tty_atexit);

	interactive_shell_session(my_ssh_session);
	tcsetattr(0, TCSANOW, &orig_termios);

	//show_remote_processes(my_ssh_session);
	
	ssh_disconnect(my_ssh_session);
	ssh_free(my_ssh_session);
}

int match( const char *reference, const char *buffer, ssize_t bufsize );

int interactive_shell_session(ssh_session session) {
	int rc;
	char buffer[256];
	int nbytes;
	int nwritten;

	ssh_channel channel = ssh_channel_new(session);

        if (channel == NULL)
                return SSH_ERROR;

        rc = ssh_channel_open_session(channel);
        if (rc != SSH_OK) {
                ssh_channel_free(channel);
        }

	rc = ssh_channel_request_pty(channel);
	if (rc != SSH_OK) return rc;
	rc = ssh_channel_change_pty_size(channel, 80, 24);
	if (rc != SSH_OK) return rc;
	rc = ssh_channel_request_shell(channel);
	if (rc != SSH_OK) return rc;

	char compare[100];
	if(!strcmp(priv_type,"sudo")){
		sprintf(compare,"[sudo] password for %s:",user);
	}else{
		sprintf(compare,"Password:");
	}

	int priv_done=0, priv_issued=0;
	char priv_cmd[100];

	if(priv_user!=NULL){
		if(!strcmp(priv_user,"root")){
			sprintf(priv_cmd,"%s bash\n",priv_type);
		}else{
			sprintf(priv_cmd,"%s -u %s bash\n",priv_type,priv_user);
		}
	}

	while (ssh_channel_is_open(channel) && !ssh_channel_is_eof(channel)) {
		struct timeval timeout;
		ssh_channel in_channels[2], out_channels[2];
		fd_set fds;
		int maxfd;
		timeout.tv_sec = 30;
		timeout.tv_usec = 0;
		in_channels[0] = channel;
		in_channels[1] = NULL;

		FD_ZERO(&fds);
		FD_SET(0, &fds);
		FD_SET(ssh_get_fd(session), &fds);

		maxfd = ssh_get_fd(session) + 1;
		ssh_select(in_channels, out_channels, maxfd, &fds, &timeout);

		if (out_channels[0] != NULL) {
			nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
			if (nbytes < 0) 
				return SSH_ERROR;
			if (nbytes > 0) {
				nwritten = write(1, buffer, nbytes);

				//log in to privileged user account
				if(priv_type!=NULL){
					if(!priv_issued){
						nwritten = ssh_channel_write(channel, priv_cmd, strlen(priv_cmd) );
						nwritten=nbytes;
						priv_issued=1;
					}

					//enter password
					if(priv_issued && !priv_done){
						rc=match( compare, buffer, nwritten );
						if( compare[rc]=='\0' ){
							sprintf(password,"%s\n",password);
							nwritten = ssh_channel_write(channel, password, sizeof(password) );
							nwritten=nbytes;
							priv_done=1;
						}
					}
				}

				if (nwritten != nbytes) 
					return SSH_ERROR;
			}
		}

		if (FD_ISSET(0, &fds)) {
			nbytes = read(0, buffer, sizeof(buffer));
			if (nbytes < 0) 
				return SSH_ERROR;
			if (nbytes > 0) {
				nwritten = ssh_channel_write(channel, buffer, nbytes);
				if (nbytes != nwritten) 
					return SSH_ERROR;
			}
		}
	}

	return rc;
}

int match( const char *reference, const char *buffer, ssize_t bufsize )
{
    int state=0;
    int i;
    for( i=0;reference[state]!='\0' && i<bufsize; ++i ) {
        if( reference[state]==buffer[i] )
            state++;
        else {
            state=0;
            if( reference[state]==buffer[i] )
                state++;
        }
    }

    return state;
}


int show_remote_processes(ssh_session session) {
	ssh_channel channel;
	int rc;
	char buffer[256];
	unsigned int nbytes;

	channel = ssh_channel_new(session);
	if (channel == NULL)
		return SSH_ERROR;

	rc = ssh_channel_open_session(channel);
	if (rc != SSH_OK) {
		ssh_channel_free(channel);
		return rc;
	}

	rc = ssh_channel_request_exec(channel, "ps aux");
	if (rc != SSH_OK) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return rc;
	}

	nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	while (nbytes > 0) {
		if (write(1, buffer, nbytes) != nbytes) {
			ssh_channel_close(channel);
			ssh_channel_free(channel);
			return SSH_ERROR;
		}
		nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
	}

	if (nbytes < 0) {
		ssh_channel_close(channel);
		ssh_channel_free(channel);
		return SSH_ERROR;
	}

	ssh_channel_send_eof(channel);
	ssh_channel_close(channel);
	ssh_channel_free(channel);
	return SSH_OK;
}


