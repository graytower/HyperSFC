#include <iostream>
#include <stdio.h>
#include <sys/stat.h>
#include <string>
#include <fstream>
#include <stdlib.h>
#include <unistd.h>
using namespace std;

bool isExist(string& name){
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}

int main()
{   
    string filename = "s1.txt";
    while(true){
        //detect s1.txt
        bool y = isExist(filename);
        if(y){
            //table_add
            system("sudo simple_switch_CLI --thrift-port 9090 <s1.txt");
            cout<<"add"<<endl;
            //delete 
            system("rm s1.txt");
            cout<<"del"<<endl;
        }
        sleep(0.0000001);
    }
}


