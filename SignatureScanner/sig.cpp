#include "sigscanner.h"
#include <limits>

using namespace std;

int main()
{
	LPCSTR Signature = "\x64\x00\x00\x00\xB0\x31\x3A\x00\x66";
	LPCSTR Mask = "xxxxxxxxx";

	SignatureScanner SigScanner;
	if (SigScanner.GetProcess("SignatureTest.exe"))
	{
		module mod = SigScanner.GetModule("SignatureTest.exe");
		// scanning for the address of the variable:
		DWORD PlayerStructBase = SigScanner.FindSignature(mod.dwBase, mod.dwSize, Signature, Mask) + 1;

		// Let's read the value of it:
		cout << uppercase << hex << PlayerStructBase << endl;
		
		int RemoteHealth = SigScanner.ReadMemory<int>(PlayerStructBase);
		float RemoteRank = SigScanner.ReadMemory<float>(PlayerStructBase + sizeof(char*) + sizeof(int));

		cout << "Current player Health is: " << dec << RemoteHealth << endl;
		cout << "Current player Rank is: " << dec << RemoteRank << endl;

		// let's modify it:
		/*int NewHealth = MAXINT32;
		cout << "Player new health is: " << NewHealth << endl;
		SigScanner.WriteMemory(HealtAddress, NewHealth);
		*/
		getchar();
	}
}
