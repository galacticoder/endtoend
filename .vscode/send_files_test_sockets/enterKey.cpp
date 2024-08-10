#include <iostream>
#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <X11/extensions/XTest.h>
#include <unistd.h> // for usleep

int main() {
    Display *display = XOpenDisplay(NULL);
    if (display == NULL) {
        std::cerr << "Error: Unable to open display." << std::endl;
        return -1;
    }

    // Read input
    std::cout << "Enter some input: ";
    std::string input;
    std::getline(std::cin, input);

    // Simulate pressing Enter key
    KeyCode enterKeyCode = XKeysymToKeycode(display, XK_Return);
    XTestFakeKeyEvent(display, enterKeyCode, True, 0);
    XTestFakeKeyEvent(display, enterKeyCode, False, 0);
    XFlush(display);

    // Add a delay (for example, 1 second)
    usleep(1000000); // 1 second

    XCloseDisplay(display);
    return 0;
}
