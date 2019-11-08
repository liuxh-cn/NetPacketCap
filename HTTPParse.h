#pragma once
#include<string>
#include<map>
using namespace std;

class HTTPParse {

	

public:
	string cmdLine = "";
	map<string, string> kvs;
	void parse(char * http, int len);

};