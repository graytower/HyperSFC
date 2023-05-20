#include <iostream>

#include "MyRawSocket.h"
#include "MyProtocol.h"
#include <fstream>
#include <string>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
using namespace std;

class FileStream
{
public:
    std::ofstream out;

public:
    void write(string fileName,string sentence)
    {
        out.open(fileName, ios::app);
        if (out.is_open())
        {
            out << sentence;
        }
        out.close();
    }
};

unsigned int getPID(char *recv)
{
    FILE *fp = NULL;
    char cmd[16] = {0};
    sprintf(cmd, "pidof %s", recv);
    if ((fp = popen(cmd, "r")) != NULL)
    {
        fgets(cmd, sizeof(cmd), fp);
        pclose(fp);
        fp = NULL;
    }
    unsigned int result = 0;
    result = strtol(cmd, NULL, 10);
    return result;
}

void taskset(int cid, int PID)
{
    FILE *fp = NULL;
    char cmd[48] = {0};
    sprintf(cmd, "taskset -pc %d %d | grep -v \"current\"", cid, PID);
    if ((fp = popen(cmd, "r")) != NULL)
    {
        fgets(cmd, sizeof(cmd), fp);
        pclose(fp);
        fp = NULL;
    }
    cout << cmd << endl;
}

int main()
{
    FileStream fs;
    std::string sFilename = "cpu.txt";
    int cid = 1;
    char recv[9] = "recv_lb";
    unsigned int rPID = getPID(recv);
    if (rPID == 0)
    {
        cout << "recv is not started" << endl;
    }
    else
    {
        cout << recv << "'s PID is " << rPID << endl;
        taskset(cid, rPID);
    }
    
    while (true)
    {

        string buffer;
        system("mpstat -P 1 1 1|awk 'NR==4{print $12}'>cpu.txt");
        std::ifstream fileSource(sFilename); // Creates an input file stream
        if (!fileSource)
        {
            cerr << "Canot open " << sFilename << endl;
        }
        else
        {
            // Intermediate buffer

            // By default, the >> operator reads word by workd (till whitespace)
            while (fileSource >> buffer)
            {
                cout << "get cpu remain=" << buffer << "  ";
                fs.write("cpu1_result.txt",buffer + "    ");
            }
        };
        unsigned char *data = (unsigned char *)buffer.c_str();
        unsigned char send_metadata_cpuu[1];
        if (data[1] == '.')
        {
            send_metadata_cpuu[0] = 100 - ((int)data[0]) - 48 + 128;
        }
        else if (data[3] == '.')
        {
            send_metadata_cpuu[0] = 0 + 128;
        }
        else
        {
            send_metadata_cpuu[0] = 100 - (((int)data[0] - 48) * 10 + (int)data[1] - 48) + 128;
        }

        cout << "send_CU=" << dec << ((int)send_metadata_cpuu[0] - 128) << endl;
        fs.write("cpu1_result.txt",to_string(100.0 - atof(buffer.c_str())) + "\n");
        sleep(0.1);
    }
}
