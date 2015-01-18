#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <sys/ioctl.h>
#include "ttymodes.h"

#ifdef DEBUG
 #define D if(1)
#else
 #define D if(0)
#endif

char cwd[1024];
FILE *fpdebug;

char *host, *user, *priv_user, *priv_type, *password, *jumphost;
char cmd[200];
int interactive=0;

int main(int argc, char *argv[]) {

	ssh_session my_ssh_session;
	int c, rc, passfd,i;
	int verbosity = SSH_LOG_PROTOCOL;
	struct termios orig_termios;
	char pbuff[20];

	char debug_log[1024];
        D getcwd(cwd, sizeof(cwd));

        D sprintf(debug_log,"%s/ssopass_debug.log",cwd);

        D fpdebug=fopen(debug_log, "w+");
        D fprintf(fpdebug,"cwd=%s\n",cwd);
        D fflush(fpdebug);

        while ((c = getopt(argc, argv, "+d:h:ij:p:s:t:u:")) != EOF) {
                switch (c) {
		case 'd':               /* file descriptor for passing password */
                        passfd = atoi(optarg);
			int n=read( passfd, pbuff, sizeof(pbuff) );
			if (n<1){
				fprintf(stderr,"Error: No value found on fd %d\n",passfd);
				D fprintf(fpdebug,"Error: No value found on fd %d\n",passfd);
				exit(1);
			}	
			//remove the newline when passed from the command line
			if(pbuff[n-1]=='\n')
				pbuff[n-1]='\0';
			pbuff[n]='\0';
			password=pbuff;
			D fprintf(fpdebug,"password: %s.\n",password);
        		D fflush(fpdebug);
                        break;

                case 'h':               /* host */
                        host = optarg;
                        break;

		case 'i':		/*interactive*/
			interactive = 1;
			break;

		case 'j':               /* jump host */
                        jumphost = optarg;
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

	//ssh command
	int first=1;
	while(argv[optind]!=NULL){
		if(first){
			strcpy(cmd,argv[optind]);
			first=0;
		}else{
			strcat(cmd,argv[optind]);
		}
		strcat(cmd," ");
		optind++;
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
	
	//If priviliges required, default to bash if no command given
	if(priv_type!=NULL && strlen(cmd)==0){
                strcpy(cmd,"bash\n");
	}

	if(password==NULL){
                password = getpass("Password: ");
        }

	tcgetattr(STDIN_FILENO, &orig_termios);

	// Open session and set options
	my_ssh_session = ssh_new();
	if (my_ssh_session == NULL)
		exit(-1);

	if(jumphost!=NULL){
		ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, jumphost);
	}else{
		ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host);
	}
	ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, user);
	//ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

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
		fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(my_ssh_session));
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
	int nbytes,pbytes;
	int nwritten,pwritten;

	ssh_channel channel;
	ssh_session my_jumphost_session;

	//get the terminal size
	struct winsize w;
    	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

	channel = ssh_channel_new(session);

        if (channel == NULL){
                return SSH_ERROR;
	}

        rc = ssh_channel_open_session(channel);
        if (rc != SSH_OK) {
                ssh_channel_free(channel);
        }

	rc = ssh_channel_request_pty(channel);
	if (rc != SSH_OK) return rc;
	rc = ssh_channel_change_pty_size(channel, w.ws_col, w.ws_row);
	if (rc != SSH_OK) return rc;
	rc = ssh_channel_request_shell(channel);
	if (rc != SSH_OK) return rc;

	int done=0, issued=0;
	char priv_cmd[100];
	char *prompt;
	char *loginprompt="assword:";
	char *sudoprompt="[sudo] password for";

	//Bit of logic here to work out the command to issue depending on sudo or pbrun, and whether it's via a jumpbox
	if(priv_user!=NULL){
		if(!strcmp(priv_type,"sudo")){
			//if this sudo command is via a jumpbox the first prompt will be a login prompt
			if(jumphost!=NULL){
				prompt=loginprompt;
			}else{
                		prompt=sudoprompt;
			}
        	}else{
                	prompt=loginprompt;
        	}

		//running command as root user
		if(!strcmp(priv_user,"root")){
			if(jumphost!=NULL){
                                if(!strcmp(priv_type,"pbrun")){
                                        //pbrun -h host cmd
					sprintf(priv_cmd,"pbrun -h %s %s",host,cmd);
				}else{
					//ssh host sudo cmd
					sprintf(priv_cmd,"ssh -t %s sudo %s",host,cmd);
				}
			}else{
				sprintf(priv_cmd,"%s %s",priv_type,cmd);
			}

		//running command as a different user to root
		}else{
			if(jumphost!=NULL){
				if(!strcmp(priv_type,"pbrun")){
					//pbrun -h host -u user cmd
					sprintf(priv_cmd,"pbrun -h %s -u %s %s",host,priv_user,cmd);
				}else{
					//ssh host sudo -u user cmd
					sprintf(priv_cmd,"ssh -t %s sudo -u %s %s",host,priv_user,cmd);
				}
			}else{
				//run pbrun or sudo -u user cmd	
				sprintf(priv_cmd,"%s -u %s %s",priv_type,priv_user,cmd);
			}
		}
	}

	//This is main section where we parse output, issue the sudo or pbrun command, and enter the password where prompted
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

			//clear buffer and read in line from remote output
			memset(buffer,0,sizeof(buffer));
			nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);

			if (nbytes < 0) 
				return SSH_ERROR;
			if (nbytes > 0) {

				//write remote output in buffer to stdout
				nwritten = write(1, buffer, nbytes);
				if (nwritten != nbytes)
                                        return SSH_ERROR;

				//log in to privileged user account
				if(priv_type!=NULL){

					//If running sudo -u user cmd via jumpbox we have another prompt to handle
					//assuming sudo -u user requires a password
					if(issued && done==1 && jumphost!=NULL){
						rc=match( sudoprompt, buffer, strlen(sudoprompt) );
						if( sudoprompt[rc]=='\0' ){
							pbytes=strlen(password);
							pwritten = ssh_channel_write(channel, password, pbytes);
							done=2;
						}
					}

					//sudo or pbrun command issued, now enter password (assuming user is prompted)
                                        if(issued && !done){
                                                rc=match( prompt, buffer, nwritten );
                                                if( prompt[rc]=='\0' ){
                                                        sprintf(password,"%s\n",password);
							pbytes=strlen(password);
                                                        pwritten = ssh_channel_write(channel, password, pbytes );
                                                        done=1;
                                                }
                                        }

					//run the sudo or pbrun command to log in as another user
					if(!issued){
						pbytes=strlen(priv_cmd);
                                                pwritten = ssh_channel_write(channel, priv_cmd, pbytes);
                                                issued=1;
                                        }
				
				}else{
					//run non privileged command
					if(!done){
						pbytes=strlen(cmd);
						pwritten = ssh_channel_write(channel, cmd, pbytes );
						D fprintf(fpdebug,"pwritten=%d pbytes=%d cmd=%s.\n",pwritten,pbytes,cmd);
                                        	D fflush(fpdebug);
						done=1;
					}
				}

				if (pwritten != pbytes){
					D fprintf(fpdebug,"nwritten=%d pbytes=%d\n",pwritten,pbytes);
        				D fflush(fpdebug);
					return SSH_ERROR;
				}


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


