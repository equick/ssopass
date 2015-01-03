int              tty_cbreak(int);                                       /* {Prog raw} */
int              tty_raw(int);                                          /* {Prog raw} */
int              tty_reset(int);                                        /* {Prog raw} */
void     tty_atexit(void);                                      /* {Prog raw} */
struct termios  *tty_termios(void);                     /* {Prog raw} */
