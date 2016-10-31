// SignatureTest.cpp : Defines the entry point for the console application.
//
#include <Windows.h>
#include <iostream>

using namespace std;

struct PlayerStruct
{
	int Health = 100;
	char* name = "Soldier";
	float rank = 1.05;
};

int main()
{
	PlayerStruct Player;
	cout << &Player << endl;
	cout << &Player.Health << endl;
	cout << &Player.name << endl;
	cout << &Player.rank << endl;
	cout << endl << endl;
	while (1)
	{
		cout << "Player health currently is: " << Player.Health << endl;
		cout << "Player name currently is: " << Player.name << endl;
		cout << "Player rank currently is: " << Player.rank << endl;
		cout << endl << endl;
		Sleep(10000);
	}
    return 0;
}

