#include <iostream>

using namespace std;

int main(){
	//cout << "\u02F9";	
	string str = "enter name";
	cout << "\u02F9";
	for (int i=0; i < str.length(); i++){
		cout << " ";
	}
	cout << str;
	cout << "\u02FA";
	//cout << "\u02FA";
	cout << endl;	
	cout << "\u02FB";
	for (int i=0; i < str.length(); i++){
		cout << " ";
	}
	cout << "\u02FC";
	//cout << "\u02FA";
	cout << endl;
	return 0;
}
