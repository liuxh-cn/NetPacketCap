#include"HTTPParse.h"

void HTTPParse::parse(char* data,int len) {
	size_t pos = 0, posk = 0, posv = 0;
	string k = "", v = "",http;
	char c;

	http = string(data, len);

	//http保存了上述GET请求
	while (pos != http.size())
	{
		c = http.at(pos);
		if (c == ':')
		{

			//非请求行，且消息头名称未解析
			if (!cmdLine.empty() && k.empty())
			{

				//存储消息头名称
				k = http.substr(posk, pos - posk);

				//跳过冒号和空格
				posv = pos + 2;
			}
		}

		//行尾
		else if (c == '\r' || c == '\n')
		{

			//尚未解析到消息头字段名称，且请求行也未解析过
			if (k.empty() && cmdLine.empty())
			{
				//本行应是请求行，保存之
				cmdLine = http.substr(posk, pos - posk);
			}
			else
			{

				//已解析了消息头字段名称，尚未解析字段值
				if (!k.empty() && v.empty())
				{

					//存储字段值
					v = http.substr(posv, pos - posv);
				}
			}
			posk = pos + 1;
		}

		if (!k.empty() && !v.empty() && !cmdLine.empty())
		{

			//保存消息头字段名称和值
			kvs.insert(make_pair(k, v));
			k = "";
			v = "";
		}
		++pos;
	}
}
