#include <ncurses.h>
#include <vector>
#include <iostream>
#include <string>

using namespace std;

void moveleft() {
  int x, y;
  getyx(stdscr, y, x);
  if (x > 0) {
    move(y, x - 1);
  }
}

void moveright(int& y, int& x) {
  move(y, x + 1);
}

void delete_char() {
  cout << "\b \b";
}

int main() {
  initscr();
  raw();
  // echo();
  keypad(stdscr, TRUE);

  // int new_rows = 24;
  // int new_cols = 80;
  // resizeterm(20, 20);
  // refresh();
  vector <char> saved;
  int ch;
  int cursor = 0;
  curs_set(0);

  // printw("Type something (type 'j' to stop): \n");

  while (true) {
    ch = getch();

    if (ch == KEY_LEFT) {
      curs_set(1);
      moveleft();
      cursor--;
    }
    else if (ch == KEY_RIGHT) {
      curs_set(1);
      int x, y;
      getyx(stdscr, y, x);
      if (x < saved.size()) {
        moveright(y, x);
        cursor++;
      }
    }
    else if (ch == KEY_UP) {
      continue;
    }
    else if (ch == KEY_DOWN) {
      continue;
    }

    else if (ch == KEY_BACKSPACE) {
      delch();
      cursor--;
      saved.erase(saved.begin() + cursor);
    }

    else if (ch == '\n') {
      break;
    }

    else {
      saved.insert(saved.begin() + cursor, char(ch));
      cursor++;
      // wrefresh(stdscr);
      // printw("\033[A"); //up
      // printw("\r"); //delete
      // printw("\033[K"); //from start mixed up on line 128
      // erase();

      clear();
      // napms(1);

      printf("\n");
      for (char i : saved) {
        printw("%c", i);
      }
      int x, y;
      getyx(stdscr, y, x);
      move(y, cursor);
    }
  }

  endwin();
  std::cout << "You typed: ";
  for (char i : saved) {
    cout << i;
  }
  cout << endl;

  return 0;
}