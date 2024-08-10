#include <iostream>
#include <lzma.h>
#include <zlib.h>
#include <vector>

using namespace std;

void comp(const string &text, string &comptext){
    uLong size = text.size();
    uLong maxbound = compressBound(size);
    vector<unsigned char> buffer(maxbound); 

    compress(&buffer[0],&maxbound,reinterpret_cast<const Bytef*>(text.data()),size);
    comptext.assign(reinterpret_cast<const char*>(buffer.data()), maxbound);
    
}

string decomp(string &comptext){
    uLong size = comptext.size();
    // uLong maxbound = compressBound(size);
    vector<unsigned char> buffer(size); 

    uncompress(&buffer[0],&size,reinterpret_cast<const Bytef*>(comptext.data()),size);
    // uncomptext.assign(reinterpret_cast<const char*>(buffer.data()), maxbound);
    string decompMsg(buffer.begin(), buffer.begin() + size);
    return decompMsg;
}

int main(){
    string text = "some te";
    string comptext;

    comp(text,comptext);
    cout << comptext;
    decomp(comptext);

    return 0;
}