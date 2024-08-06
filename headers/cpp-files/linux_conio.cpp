#include "../header-files/linux_conio.h"

#ifndef _WIN32

struct termios old_attributes, new_attributes;
int old_block_mode;
bool conio_mode = false;
bool should_enable_conio = false;

void enable_noblock()
{
    old_block_mode = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, old_block_mode | O_NONBLOCK);
}

void disable_noblock()
{
    fcntl(STDIN_FILENO, F_SETFL, old_block_mode);
}

void exit_handler(int s)
{
    should_enable_conio = conio_mode;
    disable_conio_mode();
    disable_noblock();

    if (s == SIGTSTP)
    {
        struct sigaction sig_handler;
        sig_handler.sa_handler = SIG_DFL; // reset signal handler to default for SIGTSTP
        sigemptyset(&sig_handler.sa_mask);
        sig_handler.sa_flags = 0;

        sigaction(SIGTSTP, &sig_handler, NULL);
        raise(SIGTSTP); // Suspend the process
    }
    else
    {
        exit(1); // Kill the process
    }
}

void cont_handler(int s)
{
    if (should_enable_conio)
    {
        should_enable_conio = false;
        enable_conio_mode();
    }

    struct sigaction sig_handler;
    sig_handler.sa_handler = exit_handler;
    sigemptyset(&sig_handler.sa_mask);
    sig_handler.sa_flags = 0;
    sigaction(SIGTSTP, &sig_handler, NULL);
}

// We need to intercept various kill/suspend signals so that we can reset the console settings if needed on Linux (Some are not possible to intercept, like SIGKILL or SIGSTOP, but this will do for now)
void setup_signal_interceptor()
{
    struct sigaction sig_handler;
    sig_handler.sa_handler = exit_handler;
    sigemptyset(&sig_handler.sa_mask);
    sig_handler.sa_flags = 0;

    sigaction(SIGINT, &sig_handler, NULL);
    sigaction(SIGTERM, &sig_handler, NULL);
    sigaction(SIGQUIT, &sig_handler, NULL);
    sigaction(SIGTSTP, &sig_handler, NULL);

    struct sigaction sig_cont_handler;
    sig_cont_handler.sa_handler = cont_handler;
    sigemptyset(&sig_cont_handler.sa_mask);
    sig_cont_handler.sa_flags = 0;

    sigaction(SIGCONT, &sig_cont_handler, NULL);
}

// allow kbhit and getch on linux
void enable_conio_mode()
{
    if (conio_mode)
    {
        return;
    }
    conio_mode = true;

    struct termios new_attributes;

    tcgetattr(STDIN_FILENO, &old_attributes);
    new_attributes = old_attributes;
    new_attributes.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_attributes);
}

// allow kbhit and getch on linux
void disable_conio_mode()
{
    if (!conio_mode)
    {
        return;
    }
    conio_mode = false;

    tcsetattr(STDIN_FILENO, TCSANOW, &old_attributes);
}

void set_default_terminal()
{
    struct termios term;
    if (tcgetattr(STDIN_FILENO, &term) != 0)
    {
        perror("tcgetattr");
        exit(EXIT_FAILURE);
    }

    term.c_iflag = ICRNL | BRKINT | IGNPAR | IXON;
    term.c_oflag = OPOST | ONLCR;
    term.c_cflag = CS8 | CREAD | CLOCAL;
    term.c_lflag = ISIG | ICANON | ECHO | ECHOE | IEXTEN | TOSTOP;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &term) != 0)
    {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
    }
}

// linux implementation of _getch()
int _getch()
{
    bool mode = conio_mode;
    if (!mode)
    {
        enable_conio_mode();
    }

    char c = getchar();

    if (!mode)
    {
        disable_conio_mode();
    }

    return c;
}

// linux implementation of _kbhit(), requires conio mode to be enabled
bool _kbhit()
{
    if (!conio_mode)
    {
        return false;
    }

    enable_noblock();
    int c = getchar();
    disable_noblock();

    // if the char returned from non-blocking getchar is not EOF, a character exists in stdin.
    if (c != EOF)
    {
        // put the character we read back onto the stdin stream
        ungetc(c, stdin);
        return true;
    }

    return false;
}

// Linux implementation of a non-blocking version of getch
int getch_noblock()
{
    enable_noblock();
    int c = _getch();
    disable_noblock();

    return c;
}

#else
// Windows versions of the functions (Windows has _getch() and _kbhit() by default)
void setup_signal_interceptor() {}
void disable_conio_mode() {}
void enable_conio_mode() {}

// Windows implementation of a non-blocking getch
int getch_noblock()
{
    if (_kbhit())
    {
        return _getch();
    }
    else
    {
        return EOF;
    }
}

#endif
