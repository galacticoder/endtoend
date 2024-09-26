#pragma once

#include <ncurses.h>
#include <thread>
#include <csignal>
#include "TlsSetup.hpp"
#include "HandleClient.hpp"

std::mutex ncursesMutex;

class Ncurses
{
public:
    static void threadSafeWrefresh(WINDOW *win)
    {
        std::lock_guard<std::mutex> lock(ncursesMutex);
        wrefresh(win);
    }

    static void startUserMenu(SSL *clientSocketSSL, const std::string &username, const std::string &privateKeyPath)
    {
        // first get keys
        EVP_PKEY *receivedPublicKey = Authentication::receiveKeysAndConnect(clientSocketSSL, username);

        valuePasser = [&receivedPublicKey](int sig)
        {
            return receivedPublicKey;
        };

        WINDOW *messageInputWindow;
        WINDOW *messageViewWindow;
        WINDOW *subwin;

        windowCleaning = [&](int sig)
        {
            CleanUp::cleanWins(subwin, messageInputWindow, messageViewWindow);
        };

        initscr();
        cbreak();
        nonl();
        noecho();
        keypad(stdscr, TRUE);

        int height = LINES;
        int width = COLS;

        int viewWindowHeight = height - 3;
        int inputWindowHeight = 3;

        messageInputWindow = newwin(inputWindowHeight, width, viewWindowHeight, 0);
        box(messageInputWindow, 0, 0);

        messageViewWindow = newwin(viewWindowHeight - 1, width - 2, 1, 1);
        box(messageViewWindow, 0, 0);

        threadSafeWrefresh(messageViewWindow);
        threadSafeWrefresh(messageInputWindow);

        mvwprintw(messageViewWindow, 0, 4, "Chat");
        threadSafeWrefresh(messageViewWindow);

        subwin = derwin(messageViewWindow, height - 6, width - 4, 1, 1);

        scrollok(subwin, TRUE);
        idlok(subwin, TRUE);

        wmove(messageInputWindow, 1, 1);

        EVP_PKEY *privateKey = LoadKey::LoadPrivateKey(privateKeyPath, 0);

        if (!privateKey)
            raise(SIGINT);

        std::thread(HandleClient::ReceiveMessages, clientSocketSSL, subwin, privateKey, receivedPublicKey, messageInputWindow).detach();

        std::thread(HandleClient::HandleInput, std::ref(username), receivedPublicKey, clientSocketSSL, subwin, messageInputWindow).join();
    }
};
