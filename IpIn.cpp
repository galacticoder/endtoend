#include <iostream>
#include <conio.h>

#define KEY_UP 72

#define KEY_DOWN 80

#define KEY_LEFT 75

#define KEY_RIGHT 77

c = getch();

// then simply compare c with those macros.
// if(c == KEY_UP)
using namespace std;

int main(){
    int k; 
    k = getch(); 
    if(k==0) 
        k = getch(); 
    switch(k) 
    { 
        case 72: 
                    break; 
        case 75: <do something> 
                    break; 
        case 77: <do something> 
                    break; 
        case 80: <do something> 
                    break;  
    }  
    return 0;
}