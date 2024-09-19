#pragma once

#include <iostream>
#include <string>
#include <cryptopp/osrng.h>
#include <ncurses.h>
#include <csignal>
#include <fmt/core.h>
#include "bcrypt.h"
#include "Encryption.hpp"
#include "ServerSettings.hpp"

#define eraseLine "\033[2K\r"
#define clearScreen "\033[2J\r"

class NcursesMenu {
private:
    inline static const std::string charSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_-+=<>?";
    
    static void signalHandleMenu(int signum) {
        curs_set(1);
        clrtoeol();
        refresh();
        endwin();
        std::cout << "Server initialization has stopped." << std::endl;
        exit(signum);
    }
    
    static std::string generatePassword(int length = 8) {
        CryptoPP::AutoSeededRandomPool random;
        std::string pass;
        
        for (int i = 0; i < length; ++i) {
            pass += charSet[random.GenerateByte() % charSet.size()];
        }
        
        std::cout << "Password: " << pass << std::endl;
        return Hash::hashData(pass);
    }

    static std::string passwordSet(const char* choice){
        switch (choice){
            case 2:
                std::cout << "Generating password for server..." << std::endl;
                ServerSettings::passwordNeeded = false;
                ServerSettings::requestNeeded = false;
                return generatePassword();
            case 3:
            case 4:
                std::cout << clearScreen <<"Server is starting up without a password..." << std::endl;
                ServerSettings::passwordNeeded = false;
                ServerSettings::requestNeeded = (choice == 4);
                return "";
            case 6:
                raise(SIGINT);
        }

        std::string password;
        std::cout << "Enter a password: ";
        std::getline(std::cin, password);

        if (password.length() < minLim) {
            std::cout << fmt::format("\nServer password must be at least {} characters long.", minLim) << std::endl;
            raise(SIGINT);
        }

        (choice == 1) ? std::cout << "Password has been set for server." << std::endl : std::cout << "Password has been set for server. Users need to request to join." << std::endl;

        ServerSettings::passwordNeeded = true;
        ServerSettings::requestNeeded = (choice == 5);

        return bcrypt::generateHash(password);
    }

public:
    static void printMenu(WINDOW* menu_win, int highlight) {
        int x = 2, y = 2;
        box(menu_win, 0, 0);
        
        const char* choices[] = {
            "Set password for server", 
            "Generate password", 
            "Don't set password", 
            "Make user request to join | without pass", 
            "Make user request to join | with pass", 
            "Exit"
        };
        
        int n_choices = sizeof(choices) / sizeof(choices[0]);
        
        for (int i = 0; i < n_choices; ++i) {
            if (highlight == i + 1) {
                wattron(menu_win, A_REVERSE);
                mvwprintw(menu_win, y, x, "%s", choices[i]);
                wattroff(menu_win, A_REVERSE);
            } else {
                mvwprintw(menu_win, y, x, "%s", choices[i]);
            }
            ++y;
        }
        
        wrefresh(menu_win);
    }

    static std::string StartMenu() {
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

        WINDOW* menu_win = newwin(height, width, starty, startx);
        keypad(menu_win, TRUE);

        int highlight = 1, choice = 0, c;

        printMenu(menu_win, highlight);
        while (choice == 0) {
            c = wgetch(menu_win);
            switch (c) {
                case KEY_UP:
                    highlight = (highlight == 1) ? n_choices : highlight - 1;
                    break;
                case KEY_DOWN:
                    highlight = (highlight == n_choices) ? 1 : highlight + 1;
                    break;
                case 10:
                    choice = highlight;
                    break;
                default:
                    break;
            }
            printMenu(menu_win, highlight);
        }

        curs_set(1);
        clrtoeol();
        refresh();
        endwin();

        return passwordSet(choice);
    }
};
 