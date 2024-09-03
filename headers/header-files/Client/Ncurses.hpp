#pragma once

#include <ncurses.h>
#include <thread>
#include <csignal>
#include "HandleClient.hpp"

std::mutex ncursesMutex;

class Ncurses
{
private:
public:
    static void threadSafeWrefresh(WINDOW *win)
    {
        std::lock_guard<std::mutex> lock(ncursesMutex);
        wrefresh(win);
    }

    static void tempSignalHandler(int signal)
    {
        CleanUp::cleanWins(subwin, messageInputWindow, messageViewWindow);
        shutdownHandler(signal);
    }

    static void startUserMenu(SSL *tlsSock, const std::string &userStr, EVP_PKEY *receivedPublicKey, EVP_PKEY *privateKey)
    {
        WINDOW *messageInputWindow;
        WINDOW *messageViewWindow;
        WINDOW *subwin;
        signal(SIGINT, tempSignalHandler);
        initscr();
        cbreak();
        nonl();
        noecho();
        keypad(stdscr, TRUE);

        int height = LINES;
        int width = COLS;

        int msg_view_h = height - 3;
        int msg_input_h = 3;

        messageInputWindow = newwin(msg_input_h, width, msg_view_h, 0);
        box(messageInputWindow, 0, 0);

        messageViewWindow = newwin(msg_view_h - 1, width - 2, 1, 1);
        box(messageViewWindow, 0, 0);

        threadSafeWrefresh(messageViewWindow);
        threadSafeWrefresh(messageInputWindow);

        mvwprintw(messageViewWindow, 0, 4, "Chat");
        threadSafeWrefresh(messageViewWindow);

        subwin = derwin(messageViewWindow, height - 6, width - 4, 1, 1);

        scrollok(subwin, TRUE);
        idlok(subwin, TRUE);

        wmove(messageInputWindow, 1, 1);

        std::thread(HandleClient::receiveMessages, tlsSock, subwin, privateKey, receivedPublicKey).detach();
        std::thread(HandleClient::handleInput, std::ref(userStr), receivedPublicKey, tlsSock, subwin, messageInputWindow).join();
    }
};
