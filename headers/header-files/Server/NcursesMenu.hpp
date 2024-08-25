#ifndef SERVERMENUANDENCRYPTION
#define SERVERMENUANDENCRYPTION

#include <iostream>
#include <string>
#include <cryptopp/osrng.h>
#include <ncurses.h>
#include <csignal>
#include <unistd.h>
#include <fmt/core.h>
#include "bcrypt.h"
#include "Encryption.hpp"

#define eraseLine "\033[2K\r"
#define clearScreen "\033[2J\r"

void signalHandleMenu(int signum);

class NcursesMenu
{
private:
    static std::string generatePassword(int &&length = 8)
    {
        CryptoPP::AutoSeededRandomPool random;
        const std::string charSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_-+=<>?";

        std::string pass;
        for (ssize_t i = 0; i < length; ++i)
        {
            pass += charSet[random.GenerateByte() % charSet.size()];
        }

        std::cout << "Password: " << pass << std::endl;
        sleep(2);
        std::cout << eraseLine;
        std::cout << "\x1b[A";
        return Hash::hashData(pass);
    }

public:
    static void printMenu(WINDOW *menu_win, int highlight)
    {
        signal(SIGINT, signalHandleMenu);
        int x, y, i;
        x = 2;
        y = 2;
        box(menu_win, 0, 0);
        const char *choices[] = {"Set password for server", "Generate password", "Dont set password", "Make user request to join | without pass", "Make user request to join | with pass", "Exit"};
        int n_choices = sizeof(choices) / sizeof(char *);

        for (i = 0; i < n_choices; ++i)
        {
            if (highlight == i + 1)
            {
                wattron(menu_win, A_REVERSE);
                mvwprintw(menu_win, y, x, "%s", choices[i]);
                wattroff(menu_win, A_REVERSE);
            }
            else
                mvwprintw(menu_win, y, x, "%s", choices[i]);
            ++y;
        }
        wrefresh(menu_win);
    }

    static std::string StartMenu()
    {
        unsigned int minLim = 6;
        signal(SIGINT, signalHandleMenu);
        initscr();
        clear();
        noecho();
        cbreak();
        curs_set(0);
        keypad(stdscr, TRUE);

        int cols = COLS;
        int lines = LINES;

        int width = 50;
        int height = 18;
        int starty = lines / 2 - height / 2;
        int startx = cols / 2 - width / 2;

        WINDOW *menu_win = newwin(height, width, starty, startx);
        keypad(menu_win, TRUE);

        const char *choices[] = {"Set password for server", "Generate password", "Dont set password", "Make user request to join | without pass", "Make user request to join | with pass", "Exit"}; // 1==set//2==gen//3==nopass//4==exit
        int n_choices = sizeof(choices) / sizeof(char *);
        int highlight = 1;
        int choice = 0;
        int c;

        printMenu(menu_win, highlight);
        while (choice == 0)
        {
            c = wgetch(menu_win);
            switch (c)
            {
            case KEY_UP:
                if (highlight == 1)
                    highlight = n_choices;
                else
                    --highlight;
                break;
            case KEY_DOWN:
                if (highlight == n_choices)
                    highlight = 1;
                else
                    ++highlight;
                break;
            case 10:
                choice = highlight;
                break;
            default:
                break;
            }
            printMenu(menu_win, highlight);
            if (choice != 0)
            {
                break;
            }
        }

        std::string password;

        curs_set(1);
        clrtoeol();
        refresh();
        endwin();

        if (choice == 1)
        {
            // std::cout << clearScreen;
            std::cout << "Enter a password: ";
            std::getline(std::cin, password);
            if (password.length() < minLim)
            {
                std::cout << fmt::format("\nServer password must be greater than or equal to {} characters", minLim) << std::endl;
                exit(1);
            }

            std::cout << std::endl;
            std::cout << eraseLine;
            std::cout << "\x1b[A";
            std::cout << eraseLine;
            std::cout << "\x1b[A";
            std::cout << "Password has been set for server" << std::endl;
            return bcrypt::generateHash(password);
        }
        else if (choice == 2)
        {
            std::cout << clearScreen;
            std::cout << "Generating password for server..." << std::endl;
            return generatePassword();
        }
        else if (choice == 3)
        {
            std::cout << clearScreen;
            std::cout << "Server is starting up without password..." << std::endl;
            return "";
        }
        else if (choice == 4) // user requests without pass
        {
            std::cout << clearScreen;
            std::cout << "Server is starting up without password and users need to request to join the server" << std::endl;
            return "PNINT4";
        }
        else if (choice == 5) // user requests with pass
        {
            // std::cout << clearScreen;
            std::cout << "Enter a password: ";
            std::getline(std::cin, password);

            if (password.length() < minLim)
            {
                std::cout << fmt::format("\nServer password must be greater than or equal to {} characters", minLim) << std::endl;
                exit(1);
            }

            std::cout << std::endl;
            std::cout << eraseLine;
            std::cout << "\x1b[A";
            std::cout << eraseLine;
            std::cout << "\x1b[A";
            std::cout << "Password has been set for server and users need to request to join the server" << std::endl;
            std::string hash = bcrypt::generateHash(password);
            hash.append("PNINT3");
            return hash;
        }
        else if (choice == 6)
        {
            raise(SIGINT);
        }
        return "";
    }
};

void signalHandleMenu(int signum)
{
    curs_set(1);
    clrtoeol();
    refresh();
    endwin();
    std::cout << "Server initialization has stopped" << std::endl;
    exit(signum);
}

#endif