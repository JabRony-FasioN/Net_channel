#include <iostream>
#include <fstream>
#include <string>
#include "bee2/defs.h"

using namespace std;

int main(){
string line;
ifstream thefile;
thefile.open ("cry_file.txt");
getline(thefile, line);

cout << line << endl;

}